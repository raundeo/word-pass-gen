import streamlit as st           # Web framework for the dashboard
import random                     # Logic for random word/number selection
import nltk                       # Natural Language Toolkit for dictionary access
from nltk.corpus import words     # Importing the English word corpus
import qrcode                     # Library to generate QR codes
from io import BytesIO            # Handles byte streams for image processing
import hashlib                    # Provides SHA-1 hashing for breach checks
import requests                   # Handles API calls to HaveIBeenPwned
import math                       # Mathematical functions for entropy logic
import pandas as pd               # DataFrames for the analytics chart

# --- 1. PAGE CONFIGURATION ---
# Sets the browser tab title, favicon, and forces a wide-screen layout.
st.set_page_config(page_title="VaultGen Pro", page_icon="🔐", layout="wide")

# --- 2. DATA LOADING (CACHED) ---
# Ensures the dictionary is only loaded once and remains in memory.
@st.cache_resource
def load_dictionary():
    try:
        # Checks for the NLTK 'words' corpus; downloads it if not found.
        nltk.data.find('corpora/words')
    except LookupError:
        nltk.download('words')
    # Returns lowercase, alphabetic words only to keep passphrases clean.
    return [w.lower() for w in words.words() if w.isalpha()]

all_words = load_dictionary() # Stores the processed dictionary for use.

# --- 3. SMART LOGIC & SECURITY FUNCTIONS ---

def get_caps_indices(word_count):
    """Calculates non-adjacent capitalization indices based on NIST standards."""
    if word_count == 2:
        return [random.randint(0, 1)] # One random index for 2-word phrases.
    elif word_count == 3:
        # Returns one random index OR indices 0 and 2 to ensure a gap.
        return [random.randint(0, 2)] if random.choice([1, 2]) == 1 else [0, 2]
    elif word_count == 4:
        # Picks pre-defined index pairs that are never side-by-side.
        return random.choice([[0, 2], [0, 3], [1, 3]])
    elif word_count == 5:
        # Ensures that if 3 words are caps, they are indices 0, 2, and 4.
        if random.choice([2, 3]) == 3:
            return [0, 2, 4]
        return random.choice([[0, 2], [0, 3], [0, 4], [1, 3], [1, 4], [2, 4]])
    return [0]

def generate_hint(password):
    """Creates a 'Zero-Knowledge' structural hint for the session history log."""
    parts = password.split("-") # Splits the phrase by hyphens.
    # Maps each part to its length and casing (e.g., [5]word).
    hint_parts = [f"[{len(p)}]{'UPPER' if p.isupper() else 'word'}" for p in parts[:-1]]
    hint_parts.append(f"suffix{len(parts[-1])}") # Adds length of the num/spec suffix.
    return " / ".join(hint_parts) # Returns a string like '[5]word / [6]UPPER / suffix3'.

def check_pwned(password):
    """Checks the HaveIBeenPwned API using k-Anonymity (Privacy-preserving)."""
    # 1. Generate SHA-1 hash of the password.
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:] # 2. Split into 5-char prefix and the rest.
    try:
        # 3. Send ONLY the prefix to the API.
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if res.status_code == 200:
            # 4. Check locally if the returned suffixes match ours.
            hashes = (line.split(':') for line in res.text.splitlines())
            for h, count in hashes:
                if h == suffix: return int(count) # Return breach count if found.
        return 0 # Return 0 if safe.
    except: return -1 # Return -1 for connection errors.

def calculate_entropy_manual(password):
    """Estimates entropy for manual user input based on character variety."""
    if not password: return 0 # Return 0 if input is empty.
    pool = 0 # Initialize character pool size.
    if any(c.islower() for c in password): pool += 26 # Add lowercase pool.
    if any(c.isupper() for c in password): pool += 26 # Add uppercase pool.
    if any(c.isdigit() for c in password): pool += 10 # Add digit pool.
    if any(not c.isalnum() for c in password): pool += 32 # Add special char pool.
    # Bits = Length * log2(Pool Size).
    return len(password) * math.log2(pool) if pool > 0 else 0

def calculate_entropy(word_count, pool_size, digit_count, spec_count):
    """Calculates precise mathematical entropy for dictionary-based passphrases."""
    # log2(WordPool^Count * DigitPool^Count * SpecialPool^Count).
    return (word_count * math.log2(max(pool_size, 1))) + math.log2(10**digit_count) + math.log2(18**spec_count)

# --- 4. SESSION STATE INITIALIZATION ---
# Initializes persistent storage for the current browser session.
for key in ['auth', 'history', 'passwords', 'strength_log']:
    if key not in st.session_state:
        if key == 'auth': st.session_state[key] = False # Login status.
        elif key in ['history', 'passwords', 'strength_log']: st.session_state[key] = [] # Data logs.

# --- 5. AUTHENTICATION ---
# Gatekeeper using Streamlit Secrets. Denies access without the Master Password.
if not st.session_state.auth:
    st.title("🔒 VaultGen Pro Access")
    master = st.secrets.get("PASSWORD", "admin123") # Defaults to 'admin123' if secret missing.
    if st.text_input("Master Password", type="password") == master:
        if st.button("Unlock"): st.session_state.auth = True; st.rerun() # Refresh on success.
    st.stop() # Stops execution here if not authenticated.

# --- 6. SIDEBAR & USER CONTROLS ---
with st.sidebar:
    st.title("⚙️ Settings")
    w_min, w_max = st.slider("Word Length Range", 4, 12, (4, 7)) # Word length constraints.
    w_num = st.slider("Word Count", 2, 5, 3) # Number of words in phrase.
    d_num = st.slider("Number of Digits", 2, 5, 5) # Number of digits in suffix.
    s_num = st.slider("Number of Specials", 1, 3, 1) # Number of specials in suffix.
    b_size = st.slider("Batch Size", 3, 10, 5) # Number of passwords per generation.
    show_raw = st.checkbox("Show Plain Text", value=True) # Toggles visibility.
    if st.button("Logout", use_container_width=True): 
        st.session_state.auth = False; st.rerun() # Resets auth and refreshes.

# Filters the dictionary based on current sidebar settings.
current_pool = [w for w in all_words if w_min <= len(w) <= w_max]
pool_size = len(current_pool) # Total words available for generation.

# --- 7. DASHBOARD UI ---
st.title("🔐 VaultGen Pro Dashboard")

# Section: Manual Password Audit Tool.
with st.expander("🔍 Check an Existing Password"):
    test_pwd = st.text_input("Enter password to test (Not saved to history)", type="password")
    if test_pwd:
        c1, c2, c3 = st.columns(3)
        m_bits = calculate_entropy_manual(test_pwd) # Calculate entropy.
        c1.metric("Entropy", f"{int(m_bits)} bits") # Display bits.
        leaks = check_pwned(test_pwd) # Check breach status.
        if leaks > 0: c2.error(f"Leaked {leaks:,} times!") # Error if found in breach.
        else: c2.success("No leaks found!") # Success if safe.
        # Evaluate strength based on NIST guidelines.
        strength_eval = 'Strong' if m_bits >= 80 else 'Moderate' if m_bits >= 60 else 'Weak'
        c3.info(f"Strength: {strength_eval}")
    st.caption("ℹ️ Manual checks use character logic; generated phrases use dictionary logic.")

st.divider()

# Generation Action Buttons.
c_gen, c_clr = st.columns(2)
if c_gen.button("🚀 Generate New Batch", use_container_width=True):
    batch = [] # Temporary list for the new passwords.
    # Expanded Specials Pool for higher complexity suffixes.
    specials_list = ['!', '@', '#', '$', '%', '&', '?', '*', '^', '=', '+', '`', '~' ,'<', '>', ':', ';', '|']
    for _ in range(b_size):
        # Pick random words from the filtered dictionary pool.
        selected = [random.choice(current_pool) for _ in range(w_num)]
        # Apply the smart non-adjacent capitalization.
        for idx in get_caps_indices(w_num): selected[idx] = selected[idx].upper()
        
        # Suffix logic: calculates digits and pads with leading zeros.
        max_v = (10**d_num) - 1
        num_part = str(random.randint(0, max_v)).zfill(d_num)
        # Picks the exact number of specials requested in settings.
        chosen_specials = "".join(random.choices(specials_list, k=s_num))
        
        # Formats the final passphrase string (e.g., word-WORD-12345!).
        pwd = "-".join(selected + [f"{num_part}{chosen_specials}"])
        # Log to session history with structural clue.
        st.session_state.history.insert(0, {"pwd": pwd, "hint": generate_hint(pwd)})
        batch.append(pwd) # Add to current batch list.
    
    st.session_state.passwords = batch # Update the session state passwords.
    # Log strength for the analytics chart.
    st.session_state.strength_log.append(calculate_entropy(w_num, pool_size, d_num, s_num))

if c_clr.button("🗑️ Reset Display", use_container_width=True):
    st.session_state.passwords = []; st.rerun() # Clears display and refreshes.

# --- 8. ANALYTICS ---
if st.session_state.passwords:
    st.divider()
    bits = calculate_entropy(w_num, pool_size, d_num, s_num) # Recalculate current bits.
    col_met, col_chart = st.columns([1, 2])
    
    with col_met:
        st.metric("Entropy", f"{int(bits)} bits") # Current entropy display.
        crack_yrs = (2**bits/100e9/31536000) # Estimate crack time (100B guesses/sec).
        st.metric("Crack Time", f"{crack_yrs:,.0f} yrs" if bits > 40 else "< 1 yr")
    
    with col_chart: 
        # DataFrame comparing current generation history vs NIST target.
        chart_df = pd.DataFrame({
            "Current Strength": st.session_state.strength_log,
            "NIST Target (80 bits)": [80] * len(st.session_state.strength_log)
        })
        # Renders line chart. Purple = Batch strength, Green = NIST target.
        st.line_chart(chart_df, color=["#DDA0DD", "#2ecc71"])

    # --- 9. PASSWORD DISPLAY & INTERACTIVE TOOLS ---
    st.divider()
    for i, pwd in enumerate(st.session_state.passwords):
        p_col, q_col, a_col = st.columns([3, 0.5, 1])
        
        with p_col:
            if show_raw:
                # Standard code block with built-in copy icon.
                st.code(pwd, language=None)
            else:
                # Masked display for sensitive screen sharing.
                st.markdown(f"<div style='padding:10px; background:#1e1e1e; border-radius:5px;'><code style='color:#ffffff;'>{'●' * len(pwd)}</code></div>", unsafe_allow_html=True)
        
        with q_col.expander("QR"):
            tab_copy, tab_sms = st.tabs(["Copy", "SMS"])
            with tab_copy:
                buf = BytesIO() # Create byte buffer.
                qrcode.make(pwd).save(buf, format="PNG") # Save QR to buffer.
                st.image(buf, caption="Scan to copy") # Display QR.
            with tab_sms:
                phone = st.text_input("Number", placeholder="+123456789", key=f"sms_{i}")
                # Mobile URI for SMS triggering.
                sms_uri = f"sms:{phone}?body=VaultGen Password: {pwd}"
                buf_s = BytesIO()
                qrcode.make(sms_uri).save(buf_s, format="PNG") # Save SMS QR.
                st.image(buf_s, caption="Scan to text") # Display SMS QR.
            
        if a_col.button("🛡️ Audit", key=f"aud_{i}"):
            leaks = check_pwned(pwd) # Audit current generated password.
            if leaks > 0: st.error(f"Leaked {leaks:,} times!") # Warning if breached.
            else: st.success("Safe!") # Success if safe.

# --- 10. FOOTER TICKER ---
if st.session_state.history:
    with st.expander("📜 Secure Session Log (Hints Only)"):
        # Display only hints to avoid leaking cleartext history in UI log.
        for item in st.session_state.history[:10]: st.write(f"Clue: {item['hint']}")

st.divider()
# Ticker for random security education tips.
st.info(random.choice([
    "💡 NIST Tip: Favor passphrases over complex short passwords.",
    "💡 Fact: Random capitalization significantly boosts entropy.",
    "💡 Logic: 80+ bits of entropy is the 'gold standard' for modern security."
]))
