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
import pandas as pd  # Added for the strength graph

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(page_title="VaultGen Pro", page_icon="🔐", layout="wide")

# --- 2. DATA LOADING (CACHED) ---
@st.cache_resource
def load_dictionary():
    try:
        nltk.data.find('corpora/words')
    except LookupError:
        nltk.download('words')
    return [w.lower() for w in words.words() if w.isalpha()]

all_words = load_dictionary()

# --- 3. SECURITY & UTILITY FUNCTIONS ---
def generate_hint(password):
    parts = password.split("-")
    hint_parts = []
    for part in parts:
        if part.isdigit() or (any(c.isdigit() for c in part) and any(not c.isalnum() for c in part)):
            hint_parts.append(f"num{len(part)}")
        elif part.isupper():
            hint_parts.append(f"[{len(part)}]UPPER")
        else:
            hint_parts.append(f"[{len(part)}]word")
    return " / ".join(hint_parts)

def check_pwned(password):
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

def calculate_entropy(word_count, pool_size):
    # Base calculation: log2(pool^count) + log2(number_pool) + log2(special_pool)
    return (word_count * math.log2(pool_size)) + math.log2(100000) + math.log2(7)

# --- 4. SESSION STATE ---
if 'auth' not in st.session_state: st.session_state.auth = False
if 'history' not in st.session_state: st.session_state.history = []
if 'passwords' not in st.session_state: st.session_state.passwords = []
if 'one_time_vault' not in st.session_state: st.session_state.one_time_vault = {}
if 'strength_log' not in st.session_state: st.session_state.strength_log = []

# --- 5. ONE-TIME LINK HANDLER ---
params = st.query_params
if "view" in params:
    token = params["view"]
    if token in st.session_state.one_time_vault:
        secret = st.session_state.one_time_vault.pop(token)
        st.balloons()
        st.success("### 🕵️ One-Time Secret Revealed")
        st.code(secret, language=None)
        st.warning("Deleted from memory. This view cannot be accessed again.")
        if st.button("Home"): st.query_params.clear(); st.rerun()
        st.stop()
    else:
        st.error("Invalid link."); st.stop()

# --- 6. MASTER PASSWORD LOGIN ---
if not st.session_state.auth:
    st.title("🔒 VaultGen Pro Login")
    master = st.secrets.get("PASSWORD", "admin123")
    entry = st.text_input("Master Password", type="password")
    if st.button("Unlock"):
        if entry == master:
            st.session_state.auth = True; st.rerun()
        else: st.error("Access Denied")
    st.stop()

# --- 7. MAIN INTERFACE ---
st.title("🔐 VaultGen Pro Dashboard")

# Sidebar Configuration
with st.sidebar:
    st.title("⚙️ Settings")
    w_len = st.slider("Word Length", 4, 12, 6)
    w_num = st.slider("Word Count", 2, 5, 3)
    b_size = st.slider("Batch Size", 3, 10, 5)
    show_raw = st.checkbox("Show Plain Text", value=True)
    if st.button("Logout", use_container_width=True):
        st.session_state.auth = False; st.rerun()

current_pool = [w for w in all_words if len(w) == w_len]
pool_size = len(current_pool)

# Action Buttons
c_gen, c_clr = st.columns(2)
if c_gen.button("🚀 Generate Passwords", use_container_width=True):
    batch = []
    specials = ['!', '@', '#', '$', '%', '&', '*']
    entropy_val = calculate_entropy(w_num, pool_size)
    
    for _ in range(b_size):
        selected = [random.choice(current_pool) for _ in range(w_num)]
        selected[random.randint(0, w_num-1)] = selected[random.randint(0, w_num-1)].upper()
        num_suffix = f"{str(random.randint(0, 99999)).zfill(5)}{random.choice(specials)}"
        pwd = "-".join(selected + [num_suffix])
        st.session_state.history.insert(0, {"pwd": pwd, "hint": generate_hint(pwd)})
        batch.append(pwd)
    
    st.session_state.passwords = batch
    st.session_state.strength_log.append(entropy_val)

if c_clr.button("🗑️ Reset Display", use_container_width=True):
    st.session_state.passwords = []
    st.rerun()

# --- 8. STRENGTH ANALYTICS ---
if st.session_state.passwords:
    st.divider()
    bits = calculate_entropy(w_num, pool_size)
    years = (2**bits / 100_000_000_000) / (3600 * 24 * 365)
    
    col_a, col_b = st.columns([1, 2])
    with col_a:
        st.subheader("📊 Current Specs")
        st.metric("Entropy", f"{int(bits)} bits")
        st.metric("Crack Time", f"{int(years):,} yrs" if years > 1 else "< 1 yr")
    
    with col_b:
        st.subheader("📈 Security Trend")
        if len(st.session_state.strength_log) > 0:
            st.line_chart(st.session_state.strength_log)
        else:
            st.info("Generate passwords to see your security trend.")

    # --- 9. PASSWORD LIST ---
    st.divider()
    for i, pwd in enumerate(st.session_state.passwords):
        p_col, q_col, a_col, l_col = st.columns([3, 0.5, 1, 1])
        color = "#DDA0DD" if i % 2 == 0 else "#90EE90"
        p_col.markdown(f"<div style='padding:10px; background:#1e1e1e; border-radius:5px;'><code style='color:{color}; font-size:1.1rem;'>{pwd if show_raw else '●'*len(pwd)}</code></div>", unsafe_allow_html=True)
        
        with q_col.expander("QR"):
            # Create the QR code object
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(pwd)
            qr.make(fit=True)
    
            # Create the image
            img = qr.make_image(fill_color="black", back_color="white")
    
            # Save it to a BytesIO buffer
            buf = BytesIO()
            img.save(buf, format="PNG")
    
            # Seek to the start of the buffer and display
            buf.seek(0)
            st.image(buf, caption="Scan with your phone")
            
        if a_col.button("🛡️ Audit", key=f"aud_{i}"):
            leaks = check_pwned(pwd)
            if leaks > 0: st.error(f"Leaked {leaks:,} times!")
            else: st.success("Safe!")

        if l_col.button("🔗 Burn Link", key=f"burn_{i}"):
            token = str(uuid.uuid4())
            st.session_state.one_time_vault[token] = pwd
            st.info(f"One-time link token: {token}")
            st.caption("Recipients access via: `?view=YOUR_TOKEN` appended to URL")

# --- 10. HISTORY ---
if st.session_state.history:
    st.divider()
    with st.expander("📜 Secure Session Log (Hints Only)"):
        for item in st.session_state.history[:10]:
            st.write(f"Clue: {item['hint']}")
        if st.checkbox("Download Full Plaintext History"):
            h_raw = "\n".join([x['pwd'] for x in st.session_state.history])
            st.download_button("💾 Download .txt", h_raw, file_name="vault_history.txt")
