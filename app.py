import streamlit as st
import json
import os
import secrets
import time
import smtplib
import logging

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from groq import Groq
from dotenv import load_dotenv

# =========================
# 🔐 LOAD ENVIRONMENT
# =========================
load_dotenv()

# Configure logging (never log secrets)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def get_secret(key: str) -> str | None:
    """Load a secret from .env first, then Streamlit secrets."""
    value = os.getenv(key)
    if value:
        return value
    try:
        return st.secrets.get(key, None)
    except Exception:
        return None


# Load credentials at startup — validate immediately
GROQ_API_KEY = get_secret("GROQ_API_KEY")
EMAIL        = get_secret("EMAIL")
PASSWORD     = get_secret("PASSWORD")  # Must be a Gmail App Password (16 chars), NOT your real password

# ── Startup diagnostics (safe — never prints actual password) ──
logger.info("=== Credential Load Check ===")
logger.info(f"EMAIL     : {'✅ loaded → ' + EMAIL if EMAIL else '❌ MISSING'}")
logger.info(f"PASSWORD  : {'✅ loaded (hidden)' if PASSWORD and len(PASSWORD) >= 16 else '❌ MISSING or too short — must be 16-char App Password'}")
logger.info(f"GROQ KEY  : {'✅ loaded' if GROQ_API_KEY else '❌ MISSING'}")

# Validate App Password length (Gmail App Passwords are exactly 16 chars, no spaces)
if PASSWORD and len(PASSWORD.replace(" ", "")) != 16:
    logger.warning(
        f"⚠️  PASSWORD length is {len(PASSWORD)} — Gmail App Passwords are exactly 16 characters. "
        "You may be using your real Gmail password, which will cause SMTPAuthenticationError."
    )

client = Groq(api_key=GROQ_API_KEY)

# =========================
# 🎨 PAGE CONFIG & STYLE
# =========================
st.set_page_config(page_title="Krishna AI", page_icon="🦚", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap');

* { font-family: 'Inter', sans-serif; }

.stApp {
    background: radial-gradient(circle at top, #0b1a2b, #05080f);
    color: white;
}

header { visibility: hidden; }

section[data-testid="stSidebar"] {
    background: rgba(255,255,255,0.05);
    backdrop-filter: blur(20px);
}

.stChatMessage {
    border-radius: 14px;
    background: rgba(255,255,255,0.06);
}

button { border-radius: 8px !important; }

.delete-btn button {
    color: #ff6b6b !important;
    background: transparent !important;
}
.delete-btn button:hover {
    background: rgba(255,0,0,0.1) !important;
}

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
# 📧 SECURE OTP SENDER
# =========================
OTP_EXPIRY_SECONDS = 300  # 5 minutes


def generate_otp(length: int = 6) -> str:
    """
    Generate a cryptographically secure numeric OTP.
    Uses secrets.randbelow() — NOT random.randint() which is predictable.
    """
    return "".join([str(secrets.randbelow(10)) for _ in range(length)])


def send_otp_email(to_email: str, otp: str) -> tuple[bool, str]:
    """
    Send OTP via Gmail SMTP with full exception handling.

    Returns (success: bool, error_message: str).

    IMPORTANT: PASSWORD in .env MUST be a Gmail App Password.
    Steps to get one:
      1. Enable 2FA → https://myaccount.google.com/security
      2. Generate App Password → https://myaccount.google.com/apppasswords
      3. Paste the 16-char token (no spaces) into .env as PASSWORD=...
    """
    if not EMAIL or not PASSWORD:
        return False, "EMAIL or PASSWORD not configured. Check your .env file."

    if not to_email or "@" not in to_email:
        return False, "Invalid recipient email address."

    # Build a proper HTML email
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "🦚 Krishna AI — Your Login OTP"
    msg["From"]    = f"Krishna AI <{EMAIL}>"
    msg["To"]      = to_email

    plain_body = f"Your Krishna AI OTP is: {otp}\nValid for {OTP_EXPIRY_SECONDS // 60} minutes."
    html_body = f"""
    <div style="font-family:Inter,sans-serif;background:#0b1a2b;padding:32px;border-radius:12px;max-width:480px;margin:auto;">
        <h2 style="color:#a78bfa;margin-bottom:8px;">🦚 Krishna AI</h2>
        <p style="color:#ccc;">Your one-time login code is:</p>
        <div style="font-size:36px;font-weight:700;letter-spacing:8px;color:#fff;background:#1e2d40;
                    padding:16px 24px;border-radius:8px;display:inline-block;margin:16px 0;">
            {otp}
        </div>
        <p style="color:#999;font-size:13px;">Valid for {OTP_EXPIRY_SECONDS // 60} minutes. Do not share this code.</p>
    </div>
    """
    msg.attach(MIMEText(plain_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        # Port 465 + SMTP_SSL is the correct approach for Gmail
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as server:
            server.ehlo()
            server.login(EMAIL, PASSWORD)
            server.send_message(msg)
            logger.info(f"OTP email sent to {to_email}")
            return True, ""

    except smtplib.SMTPAuthenticationError as e:
        # Most common cause: using real Gmail password instead of App Password
        logger.error(f"SMTPAuthenticationError: {e}")
        return False, (
            "Gmail authentication failed (535). "
            "You must use a Gmail App Password, NOT your real Gmail password. "
            "Go to: https://myaccount.google.com/apppasswords"
        )

    except smtplib.SMTPConnectError as e:
        logger.error(f"SMTPConnectError: {e}")
        return False, "Could not connect to Gmail SMTP. Check your internet connection."

    except smtplib.SMTPRecipientsRefused as e:
        logger.error(f"SMTPRecipientsRefused: {e}")
        return False, f"Recipient address '{to_email}' was refused by Gmail."

    except smtplib.SMTPException as e:
        logger.error(f"SMTPException: {e}")
        return False, f"Email sending failed: {str(e)}"

    except TimeoutError:
        logger.error("SMTP connection timed out.")
        return False, "Connection to Gmail timed out. Try again."

    except OSError as e:
        logger.error(f"Network error: {e}")
        return False, "Network error while connecting to Gmail SMTP."


# =========================
# 🔐 LOGIN FLOW
# =========================
if "user" not in st.session_state:

    st.markdown("<h1 style='text-align:center;'>🦚 Krishna AI</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center;color:#aaa;'>Sign in with your email OTP</p>",
                unsafe_allow_html=True)

    # Initialize session OTP state
    if "otp" not in st.session_state:
        st.session_state.otp       = None
        st.session_state.otp_time  = None
        st.session_state.otp_email = None

    email = st.text_input("📧 Email Address", placeholder="you@example.com")

    col_send, col_spacer = st.columns([1, 3])

    with col_send:
        if st.button("Send OTP", use_container_width=True):
            if not email or "@" not in email:
                st.error("Please enter a valid email address before sending OTP.")
            else:
                with st.spinner("Sending OTP..."):
                    otp = generate_otp(6)
                    success, err_msg = send_otp_email(email, otp)

                if success:
                    st.session_state.otp       = otp
                    st.session_state.otp_time  = time.time()
                    st.session_state.otp_email = email
                    st.success(f"✅ OTP sent to **{email}**. Valid for {OTP_EXPIRY_SECONDS // 60} minutes.")
                else:
                    st.error(f"❌ Failed to send OTP.\n\n**Reason:** {err_msg}")

    # Show OTP remaining time if active
    if st.session_state.otp_time:
        elapsed = time.time() - st.session_state.otp_time
        remaining = max(0, int(OTP_EXPIRY_SECONDS - elapsed))
        if remaining > 0:
            st.caption(f"⏱ OTP valid for **{remaining}s** more.")
        else:
            st.caption("⏰ OTP expired. Please request a new one.")

    entered = st.text_input("🔑 Enter OTP", max_chars=6, placeholder="6-digit code")

    if st.button("🚀 Login", use_container_width=True):
        if not st.session_state.otp:
            st.error("Please request an OTP first.")
        elif not st.session_state.otp_time or time.time() - st.session_state.otp_time > OTP_EXPIRY_SECONDS:
            st.error("⏰ OTP has expired. Please request a new one.")
            st.session_state.otp = None
        elif entered.strip() != st.session_state.otp:
            st.error("❌ Invalid OTP. Please try again.")
        else:
            st.session_state.user    = email
            st.session_state.chat_id = "New Chat"
            st.session_state.otp     = None  # Invalidate OTP immediately after use
            st.session_state.otp_time = None
            st.rerun()

    st.stop()

# =========================
# 🧠 MEMORY
# =========================
MEMORY_FILE = f"{st.session_state.user}_memory.json"

if os.path.exists(MEMORY_FILE):
    with open(MEMORY_FILE, "r") as f:
        memory = json.load(f)
else:
    memory = []

# =========================
# 💬 CHAT STORAGE
# =========================
CHAT_FILE = f"{st.session_state.user}_chats.json"

if os.path.exists(CHAT_FILE):
    with open(CHAT_FILE, "r") as f:
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
    st.caption(f"Logged in as `{st.session_state.user}`")

    if st.button("➕ New Chat"):
        new_chat = f"Chat {len(chats)+1}"
        chats[new_chat] = []
        st.session_state.chat_id = new_chat
        st.rerun()

    st.markdown("### Chats")

    for chat in list(chats.keys()):
        col1, col2 = st.columns([5, 1])

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
                with open(CHAT_FILE, "w") as f:
                    json.dump(chats, f, indent=2)
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
# 🧠 PROMPT BUILDER
# =========================
def build_prompt() -> str:
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

    messages.append({"role": "user", "content": msg})

    with st.chat_message("user"):
        st.write(msg)

    with st.spinner("Krishna is reflecting... 🧘"):
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "system", "content": build_prompt()}] + messages
        )

    reply = response.choices[0].message.content

    with st.chat_message("assistant"):
        placeholder = st.empty()
        text = ""
        for c in reply:
            text += c
            placeholder.markdown(text)
            time.sleep(0.004)

    messages.append({"role": "assistant", "content": reply})

    # Save memory for personal statements
    if any(x in msg.lower() for x in ["i am", "i feel", "i have"]):
        memory.append(msg)
        with open(MEMORY_FILE, "w") as f:
            json.dump(memory, f, indent=2)

    chats[st.session_state.chat_id] = messages
    with open(CHAT_FILE, "w") as f:
        json.dump(chats, f, indent=2)

# =========================
# 👤 FOOTER
# =========================
st.markdown("""
<div class="footer">
✨ Built with clarity by Yuktha 🦚
</div>
""", unsafe_allow_html=True)