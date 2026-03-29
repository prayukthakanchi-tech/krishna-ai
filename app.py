import streamlit as st
import json, os, random, smtplib
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
# 🌌 PARTICLES
# =========================
st.markdown("""
<style>
canvas { position: fixed; top:0; left:0; z-index:-1; }
</style>

<script>
const canvas = document.createElement('canvas');
document.body.appendChild(canvas);
const ctx = canvas.getContext('2d');

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

let particles = [];
for (let i = 0; i < 50; i++) {
    particles.push({
        x: Math.random()*canvas.width,
        y: Math.random()*canvas.height,
        r: Math.random()*2,
        d: Math.random()*0.7
    });
}

function draw() {
    ctx.clearRect(0,0,canvas.width,canvas.height);
    ctx.fillStyle = "rgba(255,215,0,0.5)";
    particles.forEach(p=>{
        ctx.beginPath();
        ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
        ctx.fill();
        p.y += p.d;
        if(p.y > canvas.height) p.y = 0;
    });
}
setInterval(draw,30);
</script>
""", unsafe_allow_html=True)

# =========================
# 🎨 UI FIX (ONLY INPUT FIXED)
# =========================
st.markdown("""
<style>

.stApp {
    background: radial-gradient(circle at center, #0b2a4a 0%, #02050a 70%);
    color: white;
}

section[data-testid="stSidebar"] {
    width: 260px !important;
}

.main .block-container {
    margin-left: 270px;
    max-width: 900px;
}

.header {
    text-align:center;
    font-size:32px;
    font-weight:bold;
    color:#FFD700;
}

/* ✅ FIXED EMAIL + OTP INPUT */
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
    color: rgba(255,255,255,0.9) !important;
    opacity: 1 !important;
}

/* BUTTON */
.stButton>button {
    width: 100%;
    border-radius: 12px;
    background: linear-gradient(135deg,#FFD700,#ffcc00);
    color: black !important;
    font-weight: bold;
}

/* CHAT */
.user-msg {
    background: rgba(255,255,255,0.05);
    padding:14px;
    border-radius:16px;
    margin:8px 0;
}

.ai-msg {
    background: linear-gradient(135deg,#1e3a5f,#0b1f33);
    padding:16px;
    border-radius:18px;
    margin:8px 0;
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
# LOGIN
# =========================
if "user" not in st.session_state:

    st.markdown("<div class='header'>🦚 Krishna AI</div>", unsafe_allow_html=True)

    email = st.text_input("Email", placeholder="Enter your email")

    if "otp" not in st.session_state:
        st.session_state.otp = None

    if st.button("Send OTP"):
        otp = str(random.randint(1000,9999))
        st.session_state.otp = otp
        send_otp(email, otp)
        st.success("OTP sent ✨")

    entered = st.text_input("OTP", placeholder="Enter OTP")

    if st.button("Login"):
        if entered == st.session_state.otp:
            st.session_state.user = email
            st.session_state.chat_id = "New Chat"
            st.rerun()
        else:
            st.error("Invalid OTP")

    st.stop()

# =========================
# CHAT UI
# =========================
st.markdown(f"<div class='header'>🦚 Krishna AI</div>", unsafe_allow_html=True)

if "messages" not in st.session_state:
    st.session_state.messages = []

for m in st.session_state.messages:
    st.write(m)

msg = st.chat_input("Ask Krishna...")

if msg:
    st.session_state.messages.append(msg)

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role":"user","content":msg}],
        max_tokens=120
    )

    reply = response.choices[0].message.content
    st.session_state.messages.append(reply)

    st.rerun()

st.markdown("<center>✨ Built by prayuktha_kanchi 🦚</center>", unsafe_allow_html=True)
