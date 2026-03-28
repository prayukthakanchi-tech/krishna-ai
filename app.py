import streamlit as st
import json, os, random, time, smtplib
from email.mime.text import MIMEText
from groq import Groq
from dotenv import load_dotenv

# =========================
# 🔐 LOAD KEYS
# =========================
load_dotenv()

def get_secret(key):
    return os.getenv(key) or st.secrets.get(key, None)

client = Groq(api_key=get_secret("GROQ_API_KEY"))
EMAIL = get_secret("EMAIL")
PASSWORD = get_secret("PASSWORD")

st.set_page_config(page_title="Krishna AI", page_icon="🦚", layout="wide")

# =========================
# 💎 LIQUID GLASS UI
# =========================
st.markdown("""
<style>

/* 🌌 Background */
.stApp {
    background: linear-gradient(135deg,#0b1a2b,#05080f,#0f2a44);
    color: white;
}

/* Hide header */
header {visibility:hidden;}

/* Center layout */
.block-container {
    max-width: 700px;
    margin: auto;
    padding-top: 50px;
}

/* Glass card */
.glass {
    background: rgba(255,255,255,0.05);
    padding: 25px;
    border-radius: 20px;
    backdrop-filter: blur(25px);
    border: 1px solid rgba(255,255,255,0.1);
}

/* Inputs */
input {
    background: rgba(255,255,255,0.08) !important;
    color: white !important;
    border-radius: 10px !important;
    border: 1px solid rgba(255,255,255,0.2) !important;
}

/* Labels */
label {
    color: #FFD700 !important;
}

/* Buttons */
.stButton button {
    width: 100%;
    border-radius: 12px;
    background: linear-gradient(45deg,#FFD700,#C9A227);
    color: black;
    font-weight: bold;
}

/* Chat bubbles */
.stChatMessage {
    border-radius: 14px;
    background: rgba(255,255,255,0.07);
    backdrop-filter: blur(10px);
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: rgba(255,255,255,0.05);
    backdrop-filter: blur(20px);
}

/* Mobile */
textarea, input {
    font-size: 16px !important;
}

.footer {
    position: fixed;
    bottom: 10px;
    width: 100%;
    text-align: center;
    color: #aaa;
}

</style>
""", unsafe_allow_html=True)

# =========================
# 📧 OTP
# =========================
def send_otp(email, otp):
    msg = MIMEText(f"Your OTP is {otp}")
    msg["Subject"] = "Krishna AI Login"
    msg["From"] = EMAIL
    msg["To"] = email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL, PASSWORD)
        server.send_message(msg)

# =========================
# 🔐 LOGIN
# =========================
if "user" not in st.session_state:

    st.markdown("""
    <div class="glass">
        <h1 style='text-align:center;color:#FFD700;'>🦚 Krishna AI</h1>
        <p style='text-align:center;color:#ccc;'>Talk. Reflect. Find clarity.</p>
    </div>
    """, unsafe_allow_html=True)

    email = st.text_input("📧 Email")

    if "otp" not in st.session_state:
        st.session_state.otp = None
        st.session_state.otp_time = None

    if st.button("Send OTP"):
        otp = str(random.randint(1000, 9999))
        st.session_state.otp = otp
        st.session_state.otp_time = time.time()
        send_otp(email, otp)
        st.success("OTP sent")

    entered = st.text_input("🔐 Enter OTP")

    if st.button("Login"):
        if not st.session_state.otp_time or time.time() - st.session_state.otp_time > 120:
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
chats = json.load(open(CHAT_FILE)) if os.path.exists(CHAT_FILE) else {}

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

    st.markdown("### Chats")

    for c in list(chats.keys()):
        col1, col2 = st.columns([5,1])

        with col1:
            if st.button(c, key=f"open_{c}"):
                st.session_state.chat_id = c
                st.rerun()

        with col2:
            if st.button("✕", key=f"del_{c}"):
                del chats[c]
                st.session_state.chat_id = "New Chat"
                json.dump(chats, open(CHAT_FILE,"w"), indent=2)
                st.rerun()

    if st.button("🚪 Logout"):
        st.session_state.clear()
        st.rerun()

# =========================
# 💬 CHAT
# =========================
messages = chats[st.session_state.chat_id]

st.markdown(f"### 🦚 {st.session_state.chat_id}")

for m in messages:
    with st.chat_message(m["role"]):
        st.write(m["content"])

msg = st.chat_input("Ask Krishna...")

if msg:

    if st.session_state.chat_id == "New Chat":
        title = msg[:25]
        chats[title] = chats.pop("New Chat")
        st.session_state.chat_id = title

    messages.append({"role":"user","content":msg})

    with st.chat_message("user"):
        st.write(msg)

    with st.spinner("Krishna is reflecting... 🧘"):
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role":"system","content":"You are Krishna, wise and calm."}] + messages
        )

    reply = response.choices[0].message.content

    with st.chat_message("assistant"):
        st.write(reply)

    messages.append({"role":"assistant","content":reply})

    chats[st.session_state.chat_id] = messages
    json.dump(chats, open(CHAT_FILE,"w"), indent=2)

# =========================
# FOOTER
# =========================
st.markdown("""
<div class="footer">
✨ Built with clarity by Yuktha 🦚
</div>
""", unsafe_allow_html=True)
