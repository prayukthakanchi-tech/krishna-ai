import streamlit as st
import json, os, random, smtplib, time
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

st.set_page_config(page_title="Krishna AI", page_icon="🦚", layout="wide")

# =========================
# 🎨 UI FIX
# =========================
st.markdown("""
<style>

/* Background */
.stApp {
    background: radial-gradient(circle at center, #0b2a4a 0%, #02050a 70%);
    color: white;
}

/* Header */
.header {
    text-align:center;
    font-size:32px;
    font-weight:bold;
    color:#FFD700;
}

/* INPUT FIX */
.stTextInput label {
    color: #FFD700 !important;
    font-weight: 600;
}

.stTextInput > div > div > input {
    color: white !important;
    background-color: rgba(0,0,0,0.6) !important;
    border: 1px solid rgba(255,215,0,0.4) !important;
    border-radius: 12px !important;
    padding: 10px !important;
}

.stTextInput > div > div > input::placeholder {
    color: rgba(255,255,255,0.8) !important;
    opacity: 1 !important;
}

/* BUTTON FIX */
.stButton>button {
    width: 100%;
    border-radius: 12px;
    background: linear-gradient(135deg,#FFD700,#ffcc00);
    color: black !important;
    font-weight: bold;
    border: none;
}

/* Footer */
.footer {
    text-align:center;
    color:#aaa;
    margin-top:30px;
}

</style>
""", unsafe_allow_html=True)

# =========================
# 📩 OTP EMAIL
# =========================
def send_otp(receiver, otp):
    msg = MIMEText(f"Your OTP is {otp}")
    msg["Subject"] = "Krishna AI Login"
    msg["From"] = EMAIL
    msg["To"] = receiver

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL, PASSWORD)
        server.send_message(msg)

# =========================
# LOGIN
# =========================
if "user" not in st.session_state:

    st.markdown("<div class='header'>🦚 Krishna AI</div>", unsafe_allow_html=True)

    email = st.text_input("Email", placeholder="Enter your email")

    if "otp_sent" not in st.session_state:
        st.session_state.otp_sent = False

    if "otp" not in st.session_state:
        st.session_state.otp = None

    if "timer" not in st.session_state:
        st.session_state.timer = 0

    # Send OTP
    if not st.session_state.otp_sent:
        if st.button("📩 Send OTP"):
            if email:
                otp = str(random.randint(1000,9999))
                st.session_state.otp = otp
                st.session_state.otp_sent = True
                st.session_state.timer = 30
                send_otp(email, otp)
                st.success("OTP sent ✨")
            else:
                st.warning("Enter email first")

    # OTP Input
    if st.session_state.otp_sent:

        otp_input = st.text_input("OTP", placeholder="Enter OTP")

        # Timer
        if st.session_state.timer > 0:
            st.info(f"Resend OTP in {st.session_state.timer} sec")
            time.sleep(1)
            st.session_state.timer -= 1
            st.rerun()
        else:
            if st.button("🔄 Resend OTP"):
                otp = str(random.randint(1000,9999))
                st.session_state.otp = otp
                st.session_state.timer = 30
                send_otp(email, otp)
                st.success("OTP resent ✨")

        # Login
        if st.button("🔐 Login"):
            if otp_input == st.session_state.otp:
                st.session_state.user = email
                st.success("Login successful 🎉")
                st.rerun()
            else:
                st.error("Invalid OTP")

    st.markdown("<div class='footer'>✨ Built by prayuktha_kanchi 🦚</div>", unsafe_allow_html=True)
    st.stop()

# =========================
# SIMPLE CHAT
# =========================
st.markdown("<div class='header'>🦚 Krishna AI</div>", unsafe_allow_html=True)

if "messages" not in st.session_state:
    st.session_state.messages = []

for m in st.session_state.messages:
    st.write(m)

msg = st.chat_input("Ask Krishna...")

if msg:
    st.session_state.messages.append(msg)
    st.rerun()

st.markdown("<div class='footer'>✨ Built by prayuktha_kanchi 🦚</div>", unsafe_allow_html=True)
