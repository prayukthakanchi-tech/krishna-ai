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
# 🔐 Load API Key
# =========================
load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

EMAIL = os.getenv("EMAIL")
PASSWORD = os.getenv("PASSWORD")

# =========================
# 🎨 Page Config
# =========================
st.set_page_config(page_title="Krishna AI", page_icon="🦚")

# =========================
# 🌌 ANIMATED UI
# =========================
st.markdown("""
<style>
.stApp {
    background: linear-gradient(-45deg, #0b1a2b, #000000, #1a2a3a);
    background-size: 400% 400%;
    animation: gradient 10s ease infinite;
    color: white;
}
@keyframes gradient {
    0% {background-position: 0%}
    50% {background-position: 100%}
    100% {background-position: 0%}
}

h1 {
    color: gold;
    text-shadow: 0 0 20px gold;
}

.stChatMessage {
    animation: fadeIn 0.5s ease-in;
    border-radius: 15px;
    background: rgba(255,255,255,0.05);
}

@keyframes fadeIn {
    from {opacity:0; transform:translateY(10px);}
    to {opacity:1;}
}

.footer {
    position: fixed;
    bottom: 10px;
    width: 100%;
    text-align: center;
    color: gold;
}
</style>
""", unsafe_allow_html=True)

# =========================
# 🧠 SYSTEM PROMPT
# =========================
SYSTEM_PROMPT = "You are Krishna, calm and wise."

# =========================
# 📧 SEND OTP
# =========================
def send_otp(email, otp):
    msg = MIMEText(f"Your OTP is {otp}")
    msg["Subject"] = "Krishna AI OTP 🦚"
    msg["From"] = EMAIL
    msg["To"] = email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL, PASSWORD)
        server.send_message(msg)

# =========================
# 🔐 LOGIN
# =========================
if "user" not in st.session_state:

    st.title("🔐 Enter Krishna's Realm")

    email = st.text_input("Enter your email")

    if "otp" not in st.session_state:
        st.session_state.otp = None

    if st.button("Get OTP"):
        otp = str(random.randint(1000, 9999))
        st.session_state.otp = otp
        send_otp(email, otp)
        st.success("OTP sent ✉️")

    entered = st.text_input("Enter OTP")

    if st.button("Enter"):
        if entered == st.session_state.otp:
            st.session_state.user = email
            st.rerun()
        else:
            st.error("Invalid OTP")

    st.stop()

# =========================
# 🧠 MEMORY
# =========================
FILE = f"{st.session_state.user}.json"

def load():
    if os.path.exists(FILE):
        return json.load(open(FILE))
    return []

def save(data):
    json.dump(data, open(FILE, "w"))

memory = load()

# =========================
# 🎭 HEADER
# =========================
st.image("https://i.imgur.com/6VBx3io.png", width=80)
st.title("🦚 Krishna AI Companion")

st.markdown("*Do your duty without attachment — Bhagavad Gita*")

# =========================
# 💬 CHAT
# =========================
if "messages" not in st.session_state:
    st.session_state.messages = [{"role":"system","content":SYSTEM_PROMPT}]

for m in st.session_state.messages[1:]:
    with st.chat_message(m["role"]):
        st.write(m["content"])

def type_writer(text):
    placeholder = st.empty()
    typed = ""
    for c in text:
        typed += c
        placeholder.markdown(typed)
        time.sleep(0.01)

msg = st.chat_input("Speak...")

if msg:
    st.session_state.messages.append({"role":"user","content":msg})

    with st.chat_message("user"):
        st.write(msg)

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=st.session_state.messages
    )

    reply = response.choices[0].message.content

    with st.chat_message("assistant"):
        type_writer(reply)

    st.session_state.messages.append({"role":"assistant","content":reply})

    memory.append({"u":msg,"a":reply})
    save(memory)

# =========================
# 👤 BRANDING
# =========================
st.markdown("""
<div class="footer">
✨ Created by Yuktha 🦚
</div>
""", unsafe_allow_html=True)