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
# 🎨 FINAL CLEAN UI
# =========================
st.markdown("""
<style>
.stApp {
    background: radial-gradient(circle at top,#0b1a2b,#05080f);
    color: white;
}

header {visibility:hidden;}

section[data-testid="stSidebar"] {
    background: rgba(255,255,255,0.05);
    backdrop-filter: blur(20px);
}

/* chat bubble */
.stChatMessage {
    border-radius: 14px;
    background: rgba(255,255,255,0.06);
}

/* buttons */
button {
    border-radius: 8px !important;
}

/* delete button */
.delete-btn button {
    color: #ff6b6b !important;
    background: transparent !important;
}

.delete-btn button:hover {
    background: rgba(255,0,0,0.1) !important;
}

/* footer */
.footer {
    position: fixed;
    bottom: 10px;
    width: 100%;
    text-align: center;
    color: #777;
}
</style>
""", unsafe_allow_html=True)

# =========================
# 📧 OTP
# =========================
def send_otp(email, otp):
    msg = MIMEText(f"Your Krishna AI OTP is: {otp}")
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

    st.markdown("<h1 style='text-align:center;'>🦚 Krishna AI</h1>", unsafe_allow_html=True)

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
# 🧠 MEMORY
# =========================
MEMORY_FILE = f"{st.session_state.user}_memory.json"
memory = json.load(open(MEMORY_FILE)) if os.path.exists(MEMORY_FILE) else []

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
        new_chat = f"Chat {len(chats)+1}"
        chats[new_chat] = []
        st.session_state.chat_id = new_chat
        st.rerun()

    st.markdown("### Chats")

    for chat in list(chats.keys()):
        col1, col2 = st.columns([5,1])

        with col1:
            if st.button(chat, key=f"open_{chat}"):
                st.session_state.chat_id = chat
                st.rerun()

        with col2:
            st.markdown('<div class="delete-btn">', unsafe_allow_html=True)
            if st.button("✕", key=f"del_{chat}"):
                del chats[chat]
                if st.session_state.chat_id == chat:
                    st.session_state.chat_id = "New Chat"
                json.dump(chats, open(CHAT_FILE,"w"), indent=2)
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("---")

    if st.button("🚪 Logout"):
        st.session_state.clear()
        st.rerun()

# =========================
# 🎭 HEADER
# =========================
st.markdown(f"""
<h2>🦚 Krishna AI Companion</h2>
<p style='color:#aaa;'>Current: {st.session_state.chat_id}</p>
""", unsafe_allow_html=True)

# =========================
# 🧠 PROMPT
# =========================
def build_prompt():
    base = """You are Krishna — calm, wise, compassionate.
Speak gently and clearly. Offer grounded guidance."""

    if memory:
        base += f"\nUser context: {memory[-5:]}"
    return base

# =========================
# 💬 CHAT
# =========================
messages = chats[st.session_state.chat_id]

for m in messages:
    with st.chat_message(m["role"]):
        st.write(m["content"])

# =========================
# 💬 INPUT
# =========================
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
            messages=[{"role":"system","content":build_prompt()}] + messages
        )

    reply = response.choices[0].message.content

    with st.chat_message("assistant"):
        placeholder = st.empty()
        text = ""
        for c in reply:
            text += c
            placeholder.markdown(text)
            time.sleep(0.004)

    messages.append({"role":"assistant","content":reply})

    # save memory
    if any(x in msg.lower() for x in ["i am","i feel","i have"]):
        memory.append(msg)
        json.dump(memory, open(MEMORY_FILE,"w"), indent=2)

    chats[st.session_state.chat_id] = messages
    json.dump(chats, open(CHAT_FILE,"w"), indent=2)

# =========================
# 👤 FOOTER
# =========================
st.markdown("""
<div class="footer">
✨ Built with clarity by Yuktha 🦚
</div>
""", unsafe_allow_html=True)
