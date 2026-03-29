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
# 🎨 UI + OTP BOX STYLE
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

/* OTP BOXES */
.otp-box input {
    text-align:center !important;
    font-size:20px !important;
    border-radius:10px !important;
}

/* Inputs */
.stTextInput input {
    color: white !important;
    background: rgba(0,0,0,0.6) !important;
    border: 1px solid rgba(255,215,0,0.3) !important;
}

/* Buttons */
.stButton>button {
    width: 100%;
    border-radius: 12px;
    background: linear-gradient(135deg,#FFD700,#ffcc00);
    color: black !important;
    font-weight: bold;
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
# OTP EMAIL
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
# LOGIN WITH OTP BOXES
# =========================
if "user" not in st.session_state:

    st.markdown("<div class='header'>🦚 Krishna AI</div>", unsafe_allow_html=True)

    email = st.text_input("Email", placeholder="Enter your email")

    # Session states
    if "otp" not in st.session_state:
        st.session_state.otp = None
    if "otp_sent" not in st.session_state:
        st.session_state.otp_sent = False
    if "timer" not in st.session_state:
        st.session_state.timer = 0

    # SEND OTP
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

    # OTP INPUT BOXES
    if st.session_state.otp_sent:

        st.markdown("### Enter OTP")

        cols = st.columns(4)
        otp_digits = []

        for i in range(4):
            with cols[i]:
                digit = st.text_input("", max_chars=1, key=f"otp_{i}")
                otp_digits.append(digit)

        entered_otp = "".join(otp_digits)

        # TIMER
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

        # LOGIN
        if st.button("🔐 Login"):
            if entered_otp == st.session_state.otp:
                st.session_state.user = email
                st.success("Login successful 🎉")
                st.rerun()
            else:
                st.error("Invalid OTP")

    st.markdown("<div class='footer'>✨ Built by Yuktha 🦚</div>", unsafe_allow_html=True)
    st.stop()

# =========================
# AFTER LOGIN (SIMPLE CHAT)
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
