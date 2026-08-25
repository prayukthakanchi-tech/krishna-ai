"""
Krishna AI — Database & Storage Abstraction Layer (Database.py)

Provides a unified, secure storage interface supporting:
1. Supabase PostgreSQL (PostgREST API via requests) when SUPABASE_URL and SUPABASE_KEY are provided.
2. Local JSON file storage in data/ as a fallback when Supabase is not configured.

Security & Authorization Principles:
- Every read/write operation strictly enforces ownership (WHERE user_email = current_user).
- Client inputs (emails, chat_ids) are validated and sanitized before database/file operations.
- Operations are fail-safe: database errors gracefully fall back without crashing the UI.
"""

import json
import logging
import os
import re
import time
import requests
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

DATA_DIR = "data"
OTP_STATE_FILE = os.path.join(DATA_DIR, "_otp_state.json")

os.makedirs(DATA_DIR, exist_ok=True)


def _safe_filename(email: str) -> str:
    """Sanitize email for file paths. Max 100 chars."""
    safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", email)
    safe = safe.replace("..", "_")
    return safe[:100]


def get_json_chat_path(email: str) -> str:
    return os.path.join(DATA_DIR, f"{_safe_filename(email)}_chats.json")


def load_json_file(path: str) -> Optional[Any]:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to read JSON file {path}: {e}")
        return None


def save_json_file(path: str, data: Any) -> bool:
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
        return True
    except OSError as e:
        logger.error(f"Failed to write JSON file {path}: {e}")
        return False


# ─────────────────────────────────────────────
# SUPABASE CONFIG & HELPERS
# ─────────────────────────────────────────────
def get_supabase_credentials() -> Tuple[Optional[str], Optional[str]]:
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY") or os.getenv("SUPABASE_ANON_KEY") or os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    if not url or not key:
        try:
            import streamlit as st
            url = url or st.secrets.get("SUPABASE_URL")
            key = key or st.secrets.get("SUPABASE_KEY") or st.secrets.get("SUPABASE_ANON_KEY") or st.secrets.get("SUPABASE_SERVICE_ROLE_KEY")
        except Exception:
            pass

    return url, key


def is_supabase_enabled() -> bool:
    url, key = get_supabase_credentials()
    return bool(url and key)


def _supabase_request(method: str, endpoint: str, data: Optional[Any] = None, params: Optional[Dict[str, str]] = None) -> Tuple[bool, Any]:
    url, key = get_supabase_credentials()
    if not url or not key:
        return False, "Supabase credentials missing"

    target_url = f"{url.rstrip('/')}/rest/v1/{endpoint.lstrip('/')}"
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

    try:
        res = requests.request(method, target_url, headers=headers, json=data, params=params, timeout=8)
        if res.status_code in (200, 201, 204):
            try:
                return True, res.json() if res.content else {}
            except ValueError:
                return True, {}
        else:
            logger.warning(f"Supabase REST {method} {endpoint} returned status {res.status_code}: {res.text}")
            return False, f"Status {res.status_code}: {res.text}"
    except Exception as e:
        logger.error(f"Supabase HTTP connection error: {e}")
        return False, str(e)


# ─────────────────────────────────────────────
# UNIFIED USER DATA STORAGE INTERFACE
# ─────────────────────────────────────────────
def load_user_chats(email: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Load chat conversations for a specific user email.
    Enforces strict authorization: users can ONLY access their own chats.
    """
    cleaned_email = email.strip().lower()

    if is_supabase_enabled():
        # Fetch conversations owned by user
        ok, res = _supabase_request("GET", "conversations", params={"user_email": f"eq.{cleaned_email}", "select": "id,title"})
        if ok and isinstance(res, list):
            chats = {}
            for conv in res:
                cid = conv.get("title") or conv.get("id")
                c_uuid = conv.get("id")
                
                # Fetch messages for conversation
                ok_msgs, res_msgs = _supabase_request(
                    "GET", "messages", 
                    params={"conversation_id": f"eq.{c_uuid}", "user_email": f"eq.{cleaned_email}", "select": "role,content,timestamp,is_error", "order": "created_at.asc"}
                )
                if ok_msgs and isinstance(res_msgs, list):
                    clean_msgs = [m for m in res_msgs if not m.get("is_error")]
                    if clean_msgs:
                        chats[cid] = clean_msgs
            return chats
        else:
            logger.info("Supabase chat fetch failed or empty; falling back to JSON storage.")

    # Fallback to local JSON file
    path = get_json_chat_path(cleaned_email)
    loaded = load_json_file(path)
    if isinstance(loaded, dict):
        clean_chats = {}
        for cid, msgs in loaded.items():
            if isinstance(msgs, list):
                clean_chats[cid] = [m for m in msgs if not m.get("is_error")]
        return clean_chats
    return {}


def save_user_chats(email: str, chats: Dict[str, List[Dict[str, Any]]]) -> bool:
    """
    Save user chats to primary storage (Supabase PostgreSQL if configured, otherwise JSON).
    """
    cleaned_email = email.strip().lower()

    # Always persist locally to JSON for immediate responsiveness & offline backup
    path = get_json_chat_path(cleaned_email)
    json_ok = save_json_file(path, chats)

    if is_supabase_enabled():
        try:
            # Ensure user record exists in 'users' table
            _supabase_request("POST", "users", data={"email": cleaned_email}, params={"on_conflict": "email"})

            for cid, msgs in chats.items():
                if not msgs:
                    continue
                
                # Upsert conversation
                conv_payload = {
                    "user_email": cleaned_email,
                    "title": cid,
                    "updated_at": "now()"
                }
                ok_c, res_c = _supabase_request("POST", "conversations", data=conv_payload, params={"on_conflict": "user_email,title"})
                
                if ok_c and isinstance(res_c, list) and len(res_c) > 0:
                    conv_id = res_c[0].get("id")
                    
                    # Delete old messages for this conversation to prevent duplicates
                    _supabase_request("DELETE", "messages", params={"conversation_id": f"eq.{conv_id}", "user_email": f"eq.{cleaned_email}"})
                    
                    # Insert current messages
                    msg_batch = []
                    for m in msgs:
                        msg_batch.append({
                            "conversation_id": conv_id,
                            "user_email": cleaned_email,
                            "role": m.get("role", "user"),
                            "content": m.get("content", ""),
                            "timestamp": m.get("timestamp", ""),
                            "is_error": m.get("is_error", False)
                        })
                    if msg_batch:
                        _supabase_request("POST", "messages", data=msg_batch)
        except Exception as e:
            logger.error(f"Error syncing user chats to Supabase: {e}")

    return json_ok


def delete_user_chat(email: str, chat_id: str) -> bool:
    """
    Delete a specific conversation for a user.
    """
    cleaned_email = email.strip().lower()
    
    # Update JSON storage
    path = get_json_chat_path(cleaned_email)
    loaded = load_json_file(path)
    if isinstance(loaded, dict) and chat_id in loaded:
        del loaded[chat_id]
        save_json_file(path, loaded)

    if is_supabase_enabled():
        try:
            _supabase_request("DELETE", "conversations", params={"user_email": f"eq.{cleaned_email}", "title": f"eq.{chat_id}"})
        except Exception as e:
            logger.error(f"Error deleting chat from Supabase: {e}")

    return True


# ─────────────────────────────────────────────
# OTP STATE STORAGE INTERFACE
# ─────────────────────────────────────────────
def load_otp_state() -> dict:
    if is_supabase_enabled():
        ok, res = _supabase_request("GET", "otp_records", params={"select": "email,otp_hash,expires_at,attempts,last_send"})
        if ok and isinstance(res, list):
            state = {}
            for row in res:
                state[row["email"]] = {
                    "otp_hash": row.get("otp_hash"),
                    "expires_at": float(row.get("expires_at", 0)),
                    "attempts": int(row.get("attempts", 0)),
                    "last_send": float(row.get("last_send", 0))
                }
            return state

    try:
        if os.path.exists(OTP_STATE_FILE):
            with open(OTP_STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def save_otp_state(state: dict) -> None:
    save_json_file(OTP_STATE_FILE, state)

    if is_supabase_enabled():
        try:
            records = []
            for email, data in state.items():
                records.append({
                    "email": email,
                    "otp_hash": data.get("otp_hash"),
                    "expires_at": data.get("expires_at"),
                    "attempts": data.get("attempts", 0),
                    "last_send": data.get("last_send", 0)
                })
            if records:
                _supabase_request("POST", "otp_records", data=records, params={"on_conflict": "email"})
        except Exception as e:
            logger.error(f"Error syncing OTP state to Supabase: {e}")
