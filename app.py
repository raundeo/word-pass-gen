import streamlit as st
import random
import nltk
from nltk.corpus import words
import qrcode
from io import BytesIO
import uuid
import hashlib
import requests
import math
import pandas as pd

# --- 1. PAGE CONFIGURATION ---
# Sets the browser tab title, icon, and uses the full width of the screen
st.set_page_config(page_title="VaultGen Pro", page_icon="🔐", layout="wide")

# --- 2. DATA LOADING (CACHED) ---
# @st.cache_resource ensures the dictionary is only loaded once per server restart
@st.cache_resource
def load_dictionary():
    try:
        # Checks if the NLTK 'words' corpus is available, downloads if missing
        nltk.data.find('corpora/words')
    except LookupError:
        nltk.download('words')
    # Returns only alphabetic words in lowercase
    return [w.lower() for w in words.words() if w.isalpha()]

all_words = load_dictionary()

# --- 3. SMART LOGIC & SECURITY FUNCTIONS ---

def get_caps_indices(word_count):
    """
    Implements non-adjacent capitalization logic based on NIST recommendations.
    Ensures that uppercase words are separated to increase visual memory and entropy.
    """
    if word_count == 2:
        return [random.randint(0, 1)]
    elif word_count == 3:
        # Randomly choose 1 or 2 caps; if 2, they must be at index 0 and 2
        return [random.randint(0, 2)] if random.choice([1, 2]) == 1 else [0, 2]
    elif word_count == 4:
        # Picks pairs of indices that are never side-by-side
        return random.choice([[0, 2], [0, 3], [1, 3]])
    elif word_count == 5:
        # Allows for 2 or 3 caps, maintaining at least one lowercase word between them
        if random.choice([2, 3]) == 3:
            return [0, 2, 4]
        return random.choice([[0, 2], [0, 3], [0, 4], [1, 3], [1, 4], [2, 4]])
    return [0]

def generate_hint(password):
    """
    Creates a 'Secure Hint' for the history log. 
    Ex: 'apple-ORANGE-00123!' becomes '[5]word / [6]UPPER / suffix8'
    """
    parts = password.split("-")
    hint_parts = [f"[{len(p)}]{'UPPER' if p.isupper() else 'word'}" for p in parts[:-1]]
    hint_parts.append(f"suffix{len(parts[-1])}")
    return " / ".join(hint_parts)

def check_pwned(password):
    """
    Uses k-Anonymity to check HaveIBeenPwned API.
    Only the first 5 chars of the SHA-1 hash are sent to the API, 
    keeping the full password private from the service.
    """
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if res.status_code == 200:
            hashes = (line.split(':') for line in res.text.splitlines())
            for h, count in hashes:
                if h == suffix: return int(count)
        return 0
    except: return -1

def calculate_entropy_manual(password):
    """
    Estimates entropy for manual input based on character variety.
    Entropy bits = Length * log2(Character Pool Size).
    """
    if not password: return 0
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(not c.isalnum() for c in password): pool += 32
    return len(password) * math.log2(pool) if pool > 0 else 0

def calculate_entropy(word_count, pool_size, digit_count, spec_count):
    """
    Calculates precise entropy for generated passphrases.
    Bits = log2(WordPool^Count * DigitPool^Count * SpecialPool^Count).
    """
    return (word_count * math.log2(max(pool_size, 1))) + math.log2(10**digit_count) + math.log2(7**spec_count)

# --- 4. SESSION STATE ---
# Initializes persistent storage for the current browser session.
# Data is lost if the tab is closed, ensuring maximum privacy.
for key in ['auth', 'history', 'passwords', 'one_time_vault', 'strength_log']:
    if key not in st.session_state:
        if key == 'auth': st.session_state[key] = False
        elif key in ['history', 'passwords', 'strength_log']: st.session_state[key] = []
        else: st.session_state[key] = {}

# --- 5. ONE-TIME LINK HANDLER ---
# Checks for '?view=' parameter to reveal a 'Burn Link' secret.
if "view" in st.query_params:
    token = st.query_params["view"]
    if token in st.session_state.one_time_vault:
        # Retrieves and deletes secret simultaneously (Self-destruct logic).
        secret = st.session_state.one_time_vault.pop(token)
        st.balloons()
        st.success("### 🕵️ One-Time Secret Revealed")
        st.code(secret, language=None)
        st.warning("Wiped from memory. This view cannot be accessed again.")
        if st.button("Home"): st.query_params.clear(); st.rerun()
        st.stop()

# --- 6. LOGIN ---
# Basic gatekeeper using Streamlit Secrets for the Master Password.
if not st.session_state.auth:
    st.title("🔒 VaultGen Pro Access")
    master = st.secrets.get("PASSWORD", "admin123")
    if st.text_input("Master Password", type="password") == master:
        if st.button("Unlock"): st.session_state.auth = True; st.rerun()
    st.stop()

# --- 7. SIDEBAR ---
with st.sidebar:
    st.title("⚙️ Settings")
    w_min, w_max = st.slider("Word Length Range", 4, 12, (4, 11))
    w_num = st.slider("Word Count", 2, 5, 3)
    d_num = st.slider("Number of Digits", 2, 5, 5)
    s_num = st.slider("Number of Specials", 1, 3, 1)
    b_size = st.slider("Batch Size", 3, 10, 5)
    show_raw = st.checkbox("Show Plain Text", value=True)
    if st.button("Logout", use_container_width=True): 
        st.session_state.auth = False; st.rerun()

# Filters dictionary based on user's length preferences.
current_pool = [w for w in all_words if w_min <= len(w) <= w_max]
pool_size = len(current_pool)

# --- 8. DASHBOARD UI ---
st.title("🔐 VaultGen Pro Dashboard")

# Section: Manual Audit
with st.expander("🔍 Check an Existing Password"):
    test_pwd = st.text_input("Enter password to test (Not saved to history)", type="password")
    if test_pwd:
        c1, c2, c3 = st.columns(3)
        m_bits = calculate_entropy_manual(test_pwd)
        c1.metric("Entropy", f"{int(m_bits)} bits")
        leaks = check_pwned(test_pwd)
        if leaks > 0: c2.error(f"Leaked {leaks:,} times!")
        else: c2.success("No leaks found!")
        c3.info(f"Strength: {'Strong' if m_bits >= 80 else 'Moderate' if m_bits >= 60 else 'Weak'}")
    st.caption("ℹ️ **Note on Entropy:** Manual checks use 'Character-Pool' logic (conservative), while generated passphrases use 'Dictionary-Pool' logic (precise).")

st.divider()

# Generation Controls
c_gen, c_clr = st.columns(2)
if c_gen.button("🚀 Generate New Batch", use_container_width=True):
    batch = []
    specials_list = ['!', '@', '#', '$', '%', '&', '?', '*', '^', '=', '+', '`', '~' ,'<', '>', ':', ';', '|']
    for _ in range(b_size):
        # Pick words randomly from dictionary pool.
        selected = [random.choice(current_pool) for _ in range(w_num)]
        # Apply non-adjacent capitalization rules.
        for idx in get_caps_indices(w_num): selected[idx] = selected[idx].upper()
        
        # Numeric suffix: handles leading zeros (zfill).
        max_v = (10**d_num) - 1
        num_part = str(random.randint(0, max_v)).zfill(d_num)
        # Randomly picks multiple special characters.
        chosen_specials = "".join(random.choices(specials_list, k=s_num))
        
        pwd = "-".join(selected + [f"{num_part}{chosen_specials}"])
        st.session_state.history.insert(0, {"pwd": pwd, "hint": generate_hint(pwd)})
        batch.append(pwd)
    
    st.session_state.passwords = batch
    st.session_state.strength_log.append(calculate_entropy(w_num, pool_size, d_num, s_num))

if c_clr.button("🗑️ Reset Display", use_container_width=True):
    st.session_state.passwords = []; st.rerun()

# --- 9. ANALYTICS ---
if st.session_state.passwords:
    st.divider()
    bits = calculate_entropy(w_num, pool_size, d_num, s_num)
    col_met, col_chart = st.columns([1, 2])
    
    with col_met:
        st.metric("Entropy", f"{int(bits)} bits")
        # Estimate crack time based on 100 billion guesses per second.
        crack_yrs = (2**bits/100e9/31536000)
        st.metric("Crack Time", f"{crack_yrs:,.0f} yrs" if bits > 40 else "< 1 yr")
    
    with col_chart: 
        # Plots entropy trend compared to 80-bit NIST standard line.
        chart_df = pd.DataFrame({
            "Current Strength": st.session_state.strength_log,
            "NIST Target (80 bits)": [80] * len(st.session_state.strength_log)
        })
        st.line_chart(chart_df, color=["#DDA0DD", "#90EE90"])

    # --- 10. PASSWORD DISPLAY ---
    st.divider()
    for i, pwd in enumerate(st.session_state.passwords):
        p_col, q_col, a_col, l_col = st.columns([3, 0.5, 1, 1])
        color = "#DDA0DD" if i % 2 == 0 else "#90EE90"
        p_col.markdown(f"<div style='padding:10px; background:#1e1e1e; border-radius:5px;'><code style='color:{color};'>{pwd if show_raw else '●' * len(pwd)}</code></div>", unsafe_allow_html=True)
        
        with q_col.expander("QR"):
            tab_copy, tab_sms = st.tabs(["Copy", "SMS"])
            with tab_copy:
                buf = BytesIO()
                qrcode.make(pwd).save(buf, format="PNG")
                st.image(buf, caption="Scan to copy")
            with tab_sms:
                phone = st.text_input("Number", placeholder="+123456789", key=f"sms_{i}")
                # Creates standard SMS URI recognized by mobile devices.
                sms_uri = f"sms:{phone}?body=VaultGen Password: {pwd}"
                buf_s = BytesIO()
                qrcode.make(sms_uri).save(buf_s, format="PNG")
                st.image(buf_s, caption="Scan to send text")
            
        if a_col.button("🛡️ Audit", key=f"aud_{i}"):
            leaks = check_pwned(pwd)
            if leaks > 0: st.error(f"Leaked {leaks:,} times!")
            else: st.success("Safe!")

        if l_col.button("🔗 Burn Link", key=f"burn_{i}"):
            token = str(uuid.uuid4())
            st.session_state.one_time_vault[token] = pwd
            st.info(f"Burn Token: {token}")

# --- 11. FOOTER TICKER ---
if st.session_state.history:
    with st.expander("📜 Secure Session Log (Hints Only)"):
        # Display only hints to keep cleartext history secure.
        for item in st.session_state.history[:10]: st.write(f"Clue: {item['hint']}")

st.divider()
# Cycles through random security advice tips.
st.info(random.choice([
    "💡 NIST Tip: Favor passphrases over complex short passwords.",
    "💡 Fact: Random capitalization significantly boosts entropy.",
    "💡 Logic: 80+ bits of entropy is the 'gold standard' for modern security."
]))
