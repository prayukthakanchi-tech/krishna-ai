import streamlit as st
import json
import os
import random
import time
import smtplib
from email.mime.text import MIMEText
from groq import Groq
from dotenv import load_dotenv

# =========================
# 🔐 LOAD KEYS
# =========================
load_dotenv()

def get_secret(key):
    try:
        return os.getenv(key) or st.secrets[key]
    except:
        return None

client = Groq(api_key=get_secret("GROQ_API_KEY"))
EMAIL = get_secret("EMAIL")
PASSWORD = get_secret("PASSWORD")

st.set_page_config(page_title="Krishna AI", page_icon="🦚", layout="centered")

# =========================
# 🎨 CLEAN GLASS UI (SAFE)
# =========================
st.markdown("""
<style>

/* Background */
.stApp {
    background: linear-gradient(135deg, #0b1a2b, #05080f);
    color: white;
}

/* Hide header */
header {visibility:hidden;}

/* Center layout */
.block-container {
    max-width: 600px;
    margin: auto;
    padding-top: 40px;
}

/* Card */
.card {
    background: rgba(255,255,255,0.05);
    padding: 20px;
    border-radius: 16px;
    backdrop-filter: blur(15px);
}

/* Labels */
label {
    color: #FFD700 !important;
}

/* Inputs */
input, textarea {
    background: rgba(255,255,255,0.1) !important;
    color: white !important;
    border-radius: 8px !important;
    border: 1px solid rgba(255,255,255,0.2) !important;
}

/* Buttons */
.stButton button {
    border-radius: 8px;
    background: linear-gradient(45deg,#FFD700,#C9A227);
    color: black;
    font-weight: bold;
}

/* Chat */
.stChatMessage {
    border-radius: 12px;
    background: rgba(255,255,255,0.06);
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: rgba(255,255,255,0.05);
}

/* Footer */
.footer {
    text-align:center;
    color:#aaa;
    margin-top:20px;
}

</style>
""", unsafe_allow_html=True)

# =========================
# 📧 OTP FUNCTION
# =========================
def send_otp(email, otp):
    msg = MIMEText(f"Your Krishna AI OTP is: {otp}")
    msg["Subject"] = "Krishna AI Login"
    msg["From"] = EMAIL
    msg["To"] = email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL, PASSWORD)
            server.send_message(msg)
    except:
        st.error("Email sending failed")

# =========================
# 🔐 LOGIN
# =========================
if "user" not in st.session_state:

    st.markdown("""
    <div class="card">
        <h2 style='text-align:center;color:#FFD700;'>🦚 Krishna AI</h2>
        <p style='text-align:center;color:#ccc;'>Calm AI companion</p>
    </div>
    """, unsafe_allow_html=True)

    email = st.text_input("Email")

    if "otp" not in st.session_state:
        st.session_state.otp = None
        st.session_state.otp_time = None

    if st.button("Send OTP"):
        otp = str(random.randint(1000, 9999))
        st.session_state.otp = otp
        st.session_state.otp_time = time.time()
        send_otp(email, otp)
        st.success("OTP sent")

    entered = st.text_input("Enter OTP")

    if st.button("Login"):
        if not st.session_state.otp_time:
            st.error("Generate OTP first")
        elif time.time() - st.session_state.otp_time > 120:
            st.error("OTP expired")
        elif entered == st.session_state.otp:
            st.session_state.user = email
            st.session_state.chat_id = "New Chat"
            st.rerun()
        else:
            st.error("Invalid OTP")

    st.stop()

# =========================
# 💬 CHAT STORAGE
# =========================
CHAT_FILE = f"{st.session_state.user}_chats.json"

if os.path.exists(CHAT_FILE):
    with open(CHAT_FILE) as f:
        chats = json.load(f)
else:
    chats = {}

if "chat_id" not in st.session_state:
    st.session_state.chat_id = "New Chat"

if st.session_state.chat_id not in chats:
    chats[st.session_state.chat_id] = []

# =========================
# 📂 SIDEBAR
# =========================
with st.sidebar:

    st.markdown("### 🦚 Krishna AI")

    if st.button("➕ New Chat"):
        new = f"Chat {len(chats)+1}"
        chats[new] = []
        st.session_state.chat_id = new
        st.rerun()

    for c in list(chats.keys()):
        col1, col2 = st.columns([4,1])

        if col1.button(c):
            st.session_state.chat_id = c
            st.rerun()

        if col2.button("✕", key=f"del_{c}"):
            del chats[c]
            st.session_state.chat_id = "New Chat"
            with open(CHAT_FILE,"w") as f:
                json.dump(chats,f)
            st.rerun()

    if st.button("Logout"):
        st.session_state.clear()
        st.rerun()

# =========================
# 💬 CHAT UI
# =========================
messages = chats[st.session_state.chat_id]

st.markdown(f"### 🦚 {st.session_state.chat_id}")

for m in messages:
    with st.chat_message(m["role"]):
        st.write(m["content"])

msg = st.chat_input("Ask Krishna...")

if msg:

    messages.append({"role":"user","content":msg})

    with st.chat_message("user"):
        st.write(msg)

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role":"system","content":"You are Krishna, calm and wise."}] + messages
    )

    reply = response.choices[0].message.content

    with st.chat_message("assistant"):
        st.write(reply)

    messages.append({"role":"assistant","content":reply})

    chats[st.session_state.chat_id] = messages
    with open(CHAT_FILE,"w") as f:
        json.dump(chats,f)

# =========================
# FOOTER
# =========================
st.markdown("""
<div class="footer">
Built by Yuktha 🦚
</div>
""", unsafe_allow_html=True)
