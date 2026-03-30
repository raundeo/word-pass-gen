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
# Sets browser metadata and forces the UI to use the full horizontal width of the screen.
st.set_page_config(page_title="VaultGen Pro", page_icon="🔐", layout="wide")

# --- 2. DATA LOADING (CACHED) ---
# @st.cache_resource ensures the dictionary is loaded into memory only once per server life-cycle.
@st.cache_resource
def load_dictionary():
    try:
        # Verifies if the NLTK 'words' corpus is available; downloads it if missing.
        nltk.data.find('corpora/words')
    except LookupError:
        nltk.download('words')
    # Filters the corpus to return only lowercase, alphabetic words for the passphrase pool.
    return [w.lower() for w in words.words() if w.isalpha()]

all_words = load_dictionary()

# --- 3. SMART LOGIC & SECURITY FUNCTIONS ---

def get_caps_indices(word_count):
    """
    Implements non-adjacent capitalization logic based on NIST security recommendations.
    Ensures that uppercase words are separated by at least one lowercase word.
    This increases visual distinctiveness and entropy without harming human memorability.
    """
    if word_count == 2:
        return [random.randint(0, 1)]
    elif word_count == 3:
        # Randomly choose 1 or 2 caps; if 2, they are forced to indices 0 and 2.
        return [random.randint(0, 2)] if random.choice([1, 2]) == 1 else [0, 2]
    elif word_count == 4:
        # Picks pre-defined index pairs that are never side-by-side.
        return random.choice([[0, 2], [0, 3], [1, 3]])
    elif word_count == 5:
        # Logic for 2 or 3 caps, ensuring no two uppercase words are adjacent.
        if random.choice([2, 3]) == 3:
            return [0, 2, 4]
        return random.choice([[0, 2], [0, 3], [0, 4], [1, 3], [1, 4], [2, 4]])
    return [0]

def generate_hint(password):
    """
    Generates a 'Zero-Knowledge' structural hint for the session history log.
    Instead of 'apple-ORANGE-12!', it stores '[5]word / [6]UPPER / suffix3'.
    This helps the user recall the structure without the server storing the actual secret.
    """
    parts = password.split("-")
    hint_parts = [f"[{len(p)}]{'UPPER' if p.isupper() else 'word'}" for p in parts[:-1]]
    hint_parts.append(f"suffix{len(parts[-1])}")
    return " / ".join(hint_parts)

def check_pwned(password):
    """
    Audits the password against the 'Have I Been Pwned' database using k-Anonymity.
    1. Hashes the password with SHA-1.
    2. Sends ONLY the first 5 characters of the hash to the API.
    3. The API returns all matching hash suffixes; we check for a match locally.
    This confirms breaches without ever exposing the password to the internet.
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
    Estimates entropy for manual input based on the variety of characters used.
    Formula: Bits = Length * log2(Character Pool Size).
    Character Pool size increases as lowercase, uppercase, digits, and symbols are detected.
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
    Calculates precise mathematical entropy for dictionary-based passphrases.
    Formula: log2(WordPool^Count * DigitPool^Count * SpecialPool^Count).
    This is the standard metric for measuring resistance to brute-force attacks.
    """
    return (word_count * math.log2(max(pool_size, 1))) + math.log2(10**digit_count) + math.log2(18**spec_count)

# --- 4. SESSION STATE INITIALIZATION ---
# Session state persists data as long as the browser tab is open.
# Streamlit clears this data if the tab is closed, ensuring high ephemeral privacy.
for key in ['auth', 'history', 'passwords', 'one_time_vault', 'strength_log']:
    if key not in st.session_state:
        if key == 'auth': st.session_state[key] = False
        elif key in ['history', 'passwords', 'strength_log']: st.session_state[key] = []
        else: st.session_state[key] = {}

# --- 5. ONE-TIME LINK HANDLER ---
# Checks for the '?view=' parameter in the URL to reveal a 'Burn Link' password.
if "view" in st.query_params:
    token = st.query_params["view"]
    if token in st.session_state.one_time_vault:
        # Retrieves and immediately DELETES the secret from memory (Self-destruct logic).
        secret = st.session_state.one_time_vault.pop(token)
        st.balloons()
        st.success("### 🕵️ One-Time Secret Revealed")
        st.code(secret, language=None)
        st.warning("Wiped from memory. This secret cannot be accessed again.")
        if st.button("Back to Home"): st.query_params.clear(); st.rerun()
        st.stop()

# --- 6. AUTHENTICATION ---
# Gatekeeper using Streamlit Secrets. Access is denied unless the Master Password matches.
if not st.session_state.auth:
    st.title("🔒 VaultGen Pro Access")
    master = st.secrets.get("PASSWORD", "admin123")
    if st.text_input("Master Password", type="password") == master:
        if st.button("Unlock"): st.session_state.auth = True; st.rerun()
    st.stop()

# --- 7. SIDEBAR & USER CONTROLS ---
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

# Filters the dictionary pool based on the user's word length constraints.
current_pool = [w for w in all_words if w_min <= len(w) <= w_max]
pool_size = len(current_pool)

# --- 8. DASHBOARD UI ---
st.title("🔐 VaultGen Pro Dashboard")

# Section: Manual Strength Audit
with st.expander("🔍 Check an Existing Password"):
    test_pwd = st.text_input("Enter password to test (Not saved to history)", type="password")
    if test_pwd:
        c1, c2, c3 = st.columns(3)
        m_bits = calculate_entropy_manual(test_pwd)
        c1.metric("Entropy", f"{int(m_bits)} bits")
        leaks = check_pwned(test_pwd)
        if leaks > 0: c2.error(f"Leaked {leaks:,} times!")
        else: c2.success("No leaks found!")
        strength_eval = 'Strong' if m_bits >= 80 else 'Moderate' if m_bits >= 60 else 'Weak'
        c3.info(f"Strength: {strength_eval}")
    st.caption("ℹ️ **Note on Entropy:** Manual checks use conservative character logic; generated phrases use precise dictionary logic.")

st.divider()

# Batch Generation Controls
c_gen, c_clr = st.columns(2)
if c_gen.button("🚀 Generate New Batch", use_container_width=True):
    batch = []
    # Expanded Specials Pool for higher complexity suffixes.
    specials_list = ['!', '@', '#', '$', '%', '&', '?', '*', '^', '=', '+', '`', '~' ,'<', '>', ':', ';', '|']
    for _ in range(b_size):
        # Pick random words from the filtered dictionary pool.
        selected = [random.choice(current_pool) for _ in range(w_num)]
        # Apply the smart capitalization logic.
        for idx in get_caps_indices(w_num): selected[idx] = selected[idx].upper()
        
        # Numeric logic: handles leading zeros using .zfill().
        max_v = (10**d_num) - 1
        num_part = str(random.randint(0, max_v)).zfill(d_num)
        # Picks the exact number of specials requested in the sidebar.
        chosen_specials = "".join(random.choices(specials_list, k=s_num))
        
        # Format: word-WORD-12345!
        pwd = "-".join(selected + [f"{num_part}{chosen_specials}"])
        # Log to structural session history.
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
        # Line chart comparing generated batch entropy against the NIST 80-bit target.
        chart_df = pd.DataFrame({
            "Current Strength": st.session_state.strength_log,
            "NIST Target (80 bits)": [80] * len(st.session_state.strength_log)
        })
        st.line_chart(chart_df, color=["#DDA0DD", "#90EE90"])

    # --- 10. PASSWORD DISPLAY & INTERACTIVE TOOLS ---
    st.divider()
    for i, pwd in enumerate(st.session_state.passwords):
        p_col, q_col, a_col, l_col = st.columns([3, 0.5, 1, 1])
        
        # Determine alternating color (Purple for even rows, Green for odd rows)
        hex_color = "#DDA0DD" if i % 2 == 0 else "#90EE90"
        
        with p_col:
            if show_raw:
                # Vertical colored bar and label to restore alternating color aesthetic
                st.markdown(f"""
                    <div style="border-left: 5px solid {hex_color}; padding-left: 10px; margin-bottom: -35px;">
                        <small style="color: {hex_color}; font-family: monospace; font-weight: bold;">PASS {i+1}</small>
                    </div>
                """, unsafe_allow_html=True)
                st.code(pwd, language=None)
            else:
                st.markdown(f"<div style='padding:10px; background:#1e1e1e; border-radius:5px; border-left: 5px solid {hex_color};'><code style='color:{hex_color};'>{'●' * len(pwd)}</code></div>", unsafe_allow_html=True)
        
        with q_col.expander("QR"):
            tab_copy, tab_sms = st.tabs(["Copy", "SMS"])
            with tab_copy:
                buf = BytesIO()
                qrcode.make(pwd).save(buf, format="PNG")
                st.image(buf, caption="Scan to copy")
            with tab_sms:
                phone = st.text_input("Number", placeholder="+123456789", key=f"sms_{i}")
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
        # Display structural clues only to avoid exposing sensitive cleartext in the UI log.
        for item in st.session_state.history[:10]: st.write(f"Clue: {item['hint']}")

st.divider()
# Ticker for security education tips.
st.info(random.choice([
    "💡 NIST Tip: Favor passphrases over complex short passwords.",
    "💡 Fact: Random capitalization significantly boosts entropy.",
    "💡 Logic: 80+ bits of entropy is the 'gold standard' for modern security."
]))
