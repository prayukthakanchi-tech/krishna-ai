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
# 🎨 UI FIX (INPUT + BUTTON PERFECT)
# =========================
st.markdown("""
<style>

/* Background */
.stApp {
    background: radial-gradient(circle at center, #0b2a4a 0%, #02050a 70%);
    color: white;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    width: 260px !important;
}

/* Layout */
.main .block-container {
    margin-left: 270px;
    max-width: 900px;
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
.stTextInput input {
    color: white !important;
    background-color: rgba(0,0,0,0.6) !important;
    border: 1px solid rgba(255,215,0,0.3) !important;
    border-radius: 12px !important;
}
.stTextInput input::placeholder {
    color: rgba(255,255,255,0.7) !important;
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

/* Chat */
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

/* Footer */
.footer {
    text-align:center;
    color:#aaa;
    margin-top:30px;
}

</style>
""", unsafe_allow_html=True)

# =========================
# 💾 MEMORY
# =========================
MEMORY_FILE = "memory.json"
memory = json.load(open(MEMORY_FILE)) if os.path.exists(MEMORY_FILE) else {}

def update_memory(text):
    if "my name is" in text.lower():
        memory["name"] = text.split("is")[-1].strip()
    json.dump(memory, open(MEMORY_FILE,"w"))

def memory_context():
    return f"User info: {memory}" if memory else ""

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
if "user" not in st.session_state:

    st.markdown("<div class='header'>🦚 Krishna AI</div>", unsafe_allow_html=True)

    email = st.text_input("Email", placeholder="Enter your email")
    entered = st.text_input("OTP", placeholder="Enter OTP")

    if "otp" not in st.session_state:
        st.session_state.otp = None

    if st.button("Send OTP"):
        otp = str(random.randint(1000,9999))
        st.session_state.otp = otp
        send_otp(email, otp)
        st.success("OTP sent ✨")

    if st.button("Login"):
        if entered == st.session_state.otp:
            st.session_state.user = email
            st.session_state.chat_id = "New Chat"
            st.rerun()
        else:
            st.error("Invalid OTP")

    st.markdown("<div class='footer'>✨ Built by Yuktha 🦚</div>", unsafe_allow_html=True)
    st.stop()

# =========================
# CHAT STORAGE
# =========================
USER = st.session_state.user
CHAT_FILE = f"{USER}_chats.json"
chats = json.load(open(CHAT_FILE)) if os.path.exists(CHAT_FILE) else {}

if "chat_id" not in st.session_state:
    st.session_state.chat_id = "New Chat"

if st.session_state.chat_id not in chats:
    chats[st.session_state.chat_id] = []

# =========================
# AUTO TITLE
# =========================
def generate_title(text):
    try:
        res = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role":"user","content":f"Give short 3 word title: {text}"}],
            max_tokens=10
        )
        return res.choices[0].message.content.strip()
    except:
        return "New Chat"

# =========================
# SIDEBAR
# =========================
with st.sidebar:
    st.markdown("### 🦚 Krishna AI")
    st.caption(USER)

    if st.button("➕ New Chat"):
        st.session_state.chat_id = "New Chat"
        chats["New Chat"] = []
        st.rerun()

    st.markdown("---")

    for c in list(chats.keys()):
        cols = st.columns([0.8, 0.2])

        with cols[0]:
            if st.button(c, key=f"chat_{c}", use_container_width=True):
                st.session_state.chat_id = c
                st.rerun()

        with cols[1]:
            if st.button("❌", key=f"del_{c}", use_container_width=True):
                del chats[c]

                if chats:
                    st.session_state.chat_id = list(chats.keys())[0]
                else:
                    chats["New Chat"] = []
                    st.session_state.chat_id = "New Chat"

                json.dump(chats, open(CHAT_FILE,"w"))
                st.rerun()

    st.markdown("---")

    if st.button("Logout"):
        st.session_state.clear()
        st.rerun()

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

    if st.session_state.chat_id == "New Chat" and len(messages) == 0:
        title = generate_title(msg)
        chats[title] = chats.pop("New Chat")
        st.session_state.chat_id = title

    messages = chats[st.session_state.chat_id]
    messages.append({"role":"user","content":msg})

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role":"system","content":memory_context()}] + messages,
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
st.markdown("<div class='footer'>✨ Built by prayuktha_kanchi 🦚</div>", unsafe_allow_html=True)
