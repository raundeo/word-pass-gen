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
# cache_resource ensures the dictionary is only loaded once per server restart
@st.cache_resource
def load_dictionary():
    try:
        nltk.data.find('corpora/words')
    except LookupError:
        nltk.download('words')
    # Returns only alphabetic words in lowercase
    return [w.lower() for w in words.words() if w.isalpha()]

all_words = load_dictionary()

# --- 3. SMART LOGIC FUNCTIONS ---
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
        # Returns a pair of indices that are never side-by-side
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
    Ex: 'apple-ORANGE-00123!' becomes '[5]word / [6]UPPER / num6'
    """
    parts = password.split("-")
    hint_parts = [f"[{len(p)}]{'UPPER' if p.isupper() else 'word'}" for p in parts[:-1]]
    hint_parts.append(f"num{len(parts[-1])}")
    return " / ".join(hint_parts)

def check_pwned(password):
    """Checks HaveIBeenPwned API using k-Anonymity (Privacy-preserving)."""
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

def calculate_entropy(word_count, pool_size, digit_count):
    """Calculates entropy: log2(Pool^Words) + log2(10^Digits) + log2(7 Specials)."""
    return (word_count * math.log2(max(pool_size, 1))) + math.log2(10**digit_count) + math.log2(7)

# --- 4. SESSION STATE ---
# Persists data across user interactions in a single tab
for key in ['auth', 'history', 'passwords', 'one_time_vault', 'strength_log']:
    if key not in st.session_state:
        if key == 'auth': st.session_state[key] = False
        elif key in ['history', 'passwords', 'strength_log']: st.session_state[key] = []
        else: st.session_state[key] = {}

# --- 5. ONE-TIME LINK HANDLER ---
if "view" in st.query_params:
    token = st.query_params["view"]
    if token in st.session_state.one_time_vault:
        secret = st.session_state.one_time_vault.pop(token)
        st.balloons()
        st.success("### 🕵️ One-Time Secret Revealed")
        st.code(secret, language=None)
        st.warning("Deleted from memory. This view cannot be accessed again.")
        if st.button("Home"): st.query_params.clear(); st.rerun()
        st.stop()
    else:
        st.error("Invalid or expired link."); st.stop()

# --- 6. LOGIN ---
if not st.session_state.auth:
    st.title("🔒 VaultGen Pro Login")
    master = st.secrets.get("PASSWORD", "admin123")
    entry = st.text_input("Master Password", type="password")
    if st.button("Unlock"):
        if entry == master:
            st.session_state.auth = True; st.rerun()
        else: st.error("Access Denied.")
    st.stop()

# --- 7. SIDEBAR ---
with st.sidebar:
    st.title("⚙️ Settings")
    w_min, w_max = st.slider("Word Length Range", 4, 12, (4, 11))
    w_num = st.slider("Word Count", 2, 5, 3)
    # NEW: User can now select 2 to 5 digits
    d_num = st.slider("Number of Digits", 2, 5, 5)
    b_size = st.slider("Batch Size", 3, 10, 5)
    show_raw = st.checkbox("Show Plain Text", value=True)
    
    st.divider()
    st.subheader("ℹ️ About")
    st.caption("VaultGen Pro uses Diceware-style logic and NIST-standard entropy calculations.")
    if st.button("Logout", use_container_width=True): 
        st.session_state.auth = False
        st.rerun()

# Filter dictionary based on slider range
current_pool = [w for w in all_words if w_min <= len(w) <= w_max]
pool_size = len(current_pool)

# --- 8. MAIN DASHBOARD ---
st.title("🔐 VaultGen Pro Dashboard")
c_gen, c_clr = st.columns(2)

if c_gen.button("🚀 Generate Passwords", use_container_width=True):
    batch = []
    specials = ['!', '@', '#', '$', '%', '&', '*']
    for _ in range(b_size):
        selected = [random.choice(current_pool) for _ in range(w_num)]
        # Apply Smart Capitalization
        for idx in get_caps_indices(w_num): selected[idx] = selected[idx].upper()
        
        # Numeric logic: Handle leading zeros based on selected d_num
        max_val = (10**d_num) - 1
        num_suffix = str(random.randint(0, max_val)).zfill(d_num)
        
        pwd = "-".join(selected + [f"{num_suffix}{random.choice(specials)}"])
        st.session_state.history.insert(0, {"pwd": pwd, "hint": generate_hint(pwd)})
        batch.append(pwd)
    
    st.session_state.passwords = batch
    st.session_state.strength_log.append(calculate_entropy(w_num, pool_size, d_num))

if c_clr.button("🗑️ Reset Display", use_container_width=True):
    st.session_state.passwords = []; st.rerun()

# --- 9. ANALYTICS ---
if st.session_state.passwords:
    st.divider()
    bits = calculate_entropy(w_num, pool_size, d_num)
    col_met, col_chart = st.columns([1, 2])
    
    with col_met:
        st.subheader("📊 Current Specs")
        st.metric("Entropy", f"{int(bits)} bits")
        crack_yrs = (2**bits/100e9/31536000)
        st.metric("Crack Time", f"{crack_yrs:,.0f} yrs" if bits > 40 else "< 1 yr")
    
    with col_chart: 
        st.subheader("📈 Security Trend vs NIST Benchmark")
        chart_data = pd.DataFrame({
            "Current Strength": st.session_state.strength_log,
            "NIST Target (80 bits)": [80] * len(st.session_state.strength_log)
        })
        st.line_chart(chart_data, color=["#DDA0DD", "#90EE90"])

    # --- 10. DISPLAY ---
    st.divider()
    for i, pwd in enumerate(st.session_state.passwords):
        p_col, q_col, a_col, l_col = st.columns([3, 0.5, 1, 1])
        color = "#DDA0DD" if i % 2 == 0 else "#90EE90"
        p_col.markdown(f"<div style='padding:10px; background:#1e1e1e; border-radius:5px;'><code style='color:{color};'>{pwd if show_raw else '●'*len(pwd)}</code></div>", unsafe_allow_html=True)
        
        with q_col.expander("QR"):
            buf = BytesIO()
            qrcode.make(pwd).save(buf, format="PNG")
            st.image(buf)
            
        if a_col.button("🛡️ Audit", key=f"aud_{i}"):
            leaks = check_pwned(pwd)
            if leaks > 0: st.error(f"Leaked {leaks:,} times!")
            elif leaks == 0: st.success("Safe!")
            else: st.warning("Service Offline")

        if l_col.button("🔗 Burn Link", key=f"burn_{i}"):
            token = str(uuid.uuid4())
            st.session_state.one_time_vault[token] = pwd
            st.info(f"Link suffix: `?view={token}`")

# --- 11. HISTORY & TIPS ---
if st.session_state.history:
    with st.expander("📜 Secure Session Log (Hints Only)"):
        for item in st.session_state.history[:10]: st.write(f"Clue: {item['hint']}")
st.divider()
tips = [
    "💡 NIST Tip: Favor passphrases (multiple words) over complex short passwords.",
    "💡 Security: Avoid using the same password for more than one account.",
    "💡 Fact: A 4-word passphrase is often harder to crack than a 10-character random string.",
    "💡 Logic: Random capitalization in passphrases significantly boosts entropy."
]
st.info(random.choice(tips))
