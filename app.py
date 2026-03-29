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
# 🌌 PARTICLE BACKGROUND (SAFE)
# =========================
st.markdown("""
<style>
canvas {
    position: fixed;
    top:0;
    left:0;
    z-index:-1;
}
</style>

<script>
const canvas = document.createElement('canvas');
document.body.appendChild(canvas);
const ctx = canvas.getContext('2d');

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

let particles = [];

for (let i = 0; i < 60; i++) {
    particles.push({
        x: Math.random()*canvas.width,
        y: Math.random()*canvas.height,
        r: Math.random()*2,
        d: Math.random()*1
    });
}

function draw() {
    ctx.clearRect(0,0,canvas.width,canvas.height);
    ctx.fillStyle = "rgba(255,215,0,0.5)";
    particles.forEach(p=>{
        ctx.beginPath();
        ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
        ctx.fill();
    });
    update();
}

function update() {
    particles.forEach(p=>{
        p.y += p.d;
        if(p.y > canvas.height) p.y = 0;
    });
}

setInterval(draw,30);
</script>
""", unsafe_allow_html=True)

# =========================
# 💾 MEMORY SYSTEM
# =========================
MEMORY_FILE = "memory.json"

if os.path.exists(MEMORY_FILE):
    memory = json.load(open(MEMORY_FILE))
else:
    memory = {}

def update_memory(text):
    t = text.lower()

    if "my name is" in t:
        memory["name"] = text.split("is")[-1].strip()

    if "i feel" in t:
        memory["feeling"] = text

    if "i like" in t:
        memory["likes"] = text

    json.dump(memory, open(MEMORY_FILE,"w"))

def memory_context():
    if not memory:
        return ""
    return f"User info: {memory}"

# =========================
# 🎨 YOUR EXISTING UI (UNCHANGED)
# =========================
st.markdown("""
<style>
.stApp {
    background: radial-gradient(circle at center, #0b2a4a 0%, #02050a 70%);
    color: white;
}
.block-container {max-width:900px;margin:auto;}
.header {
    text-align:center;
    font-size:32px;
    font-weight:bold;
    color:#FFD700;
}
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
    border:1px solid rgba(255,215,0,0.2);
}
textarea {
    background: rgba(0,0,0,0.4) !important;
    border-radius:14px !important;
    color:white !important;
}
section[data-testid="stSidebar"] {
    background: rgba(0,0,0,0.6);
}
.footer {
    text-align:center;
    color:#aaa;
    margin-top:20px;
}
</style>
""", unsafe_allow_html=True)

# =========================
# 📩 OTP
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
LOGIN_FILE = "login.json"

def save_login(user):
    json.dump({"user":user}, open(LOGIN_FILE,"w"))

def load_login():
    if os.path.exists(LOGIN_FILE):
        return json.load(open(LOGIN_FILE)).get("user")

def clear_login():
    if os.path.exists(LOGIN_FILE):
        os.remove(LOGIN_FILE)

if "user" not in st.session_state:

    saved = load_login()
    if saved:
        st.session_state.user = saved
        st.rerun()

    st.markdown("<div class='header'>🦚 Krishna AI</div>", unsafe_allow_html=True)

    email = st.text_input("Enter Email")

    if "otp" not in st.session_state:
        st.session_state.otp = None

    if st.button("Send OTP"):
        otp = str(random.randint(1000,9999))
        st.session_state.otp = otp
        send_otp(email, otp)
        st.success("OTP sent ✨")

    entered = st.text_input("Enter OTP")

    if st.button("Login"):
        if entered == st.session_state.otp:
            st.session_state.user = email
            save_login(email)
            st.session_state.chat_id = "Chat 1"
            st.rerun()
        else:
            st.error("Invalid OTP")

    st.stop()

# =========================
# CHAT STORAGE
# =========================
USER = st.session_state.user
CHAT_FILE = f"{USER}_chats.json"

if os.path.exists(CHAT_FILE):
    chats = json.load(open(CHAT_FILE))
else:
    chats = {}

if "chat_id" not in st.session_state:
    st.session_state.chat_id = "Chat 1"

if st.session_state.chat_id not in chats:
    chats[st.session_state.chat_id] = []

# =========================
# SIDEBAR
# =========================
with st.sidebar:
    st.markdown("### 🦚 Krishna AI")
    st.caption(USER)

    if st.button("➕ New Chat"):
        new = f"Chat {len(chats)+1}"
        chats[new] = []
        st.session_state.chat_id = new
        st.rerun()

    for c in chats.keys():
        if st.button(c):
            st.session_state.chat_id = c
            st.rerun()

    st.markdown("---")

    if st.button("Logout"):
        clear_login()
        st.session_state.clear()
        st.rerun()

# =========================
# 🧠 AI PROMPT (WITH MEMORY)
# =========================
SYSTEM_PROMPT = f"""
You are Krishna — speak like a real human friend.

{memory_context()}

- Short replies (2–4 lines)
- Natural tone
- Use emojis 😊
- Ask follow-up sometimes
"""

# =========================
# CHAT UI
# =========================
st.markdown(f"<div class='header'>🦚 {st.session_state.chat_id}</div>", unsafe_allow_html=True)

messages = chats[st.session_state.chat_id]

for m in messages:
    if m["role"] == "user":
        st.markdown(f"<div class='user-msg'>🙂 {m['content']}</div>", unsafe_allow_html=True)
    else:
        st.markdown(f"<div class='ai-msg'>🧘 {m['content']}</div>", unsafe_allow_html=True)

msg = st.chat_input("Ask Krishna...")

if msg:
    update_memory(msg)

    messages.append({"role":"user","content":msg})

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role":"system","content":SYSTEM_PROMPT}] + messages,
        temperature=1,
        max_tokens=120
    )

    reply = response.choices[0].message.content

    messages.append({"role":"assistant","content":reply})
    chats[st.session_state.chat_id] = messages

    json.dump(chats, open(CHAT_FILE,"w"))

    st.rerun()

# =========================
# FOOTER
# =========================
st.markdown("<div class='footer'>✨ Built by Prayuktha_kanchi 🦚</div>", unsafe_allow_html=True)
