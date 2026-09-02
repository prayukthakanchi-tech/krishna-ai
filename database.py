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
import hashlib
import base64
import secrets
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

DATA_DIR = "data"
OTP_STATE_FILE = os.path.join(DATA_DIR, "_otp_state.json")
OAUTH_PKCE_FILE = os.path.join(DATA_DIR, "_oauth_pkce.json")

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
# SUPABASE GOOGLE OAUTH HELPERS (PKCE FLOW)
# ─────────────────────────────────────────────
def create_oauth_pkce_challenge() -> Tuple[str, str]:
    """
    Generate PKCE code_verifier and code_challenge according to RFC 7636.
    Uses crypto-random secrets and SHA-256 with URL-safe base64 encoding without padding.
    """
    verifier = secrets.token_urlsafe(64)
    hashed = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(hashed).decode("ascii").rstrip("=")
    return verifier, challenge


def save_pending_pkce_verifier(state_token: str, verifier: str) -> None:
    """Store PKCE verifier keyed by state token (server-side JSON, 15 min lifetime)."""
    now = time.time()
    existing = load_json_file(OAUTH_PKCE_FILE)
    if not isinstance(existing, dict):
        existing = {}

    # Purge expired verifiers (> 15 mins)
    cleaned = {
        s: v for s, v in existing.items()
        if isinstance(v, dict) and now - float(v.get("created_at", 0)) < 900
    }
    cleaned[state_token] = {"verifier": verifier, "created_at": now}

    # Cap to 100 active states (prevent unbounded growth)
    if len(cleaned) > 100:
        oldest_keys = sorted(cleaned.keys(), key=lambda k: cleaned[k].get("created_at", 0))[:len(cleaned) - 100]
        for k in oldest_keys:
            cleaned.pop(k, None)

    save_json_file(OAUTH_PKCE_FILE, cleaned)


def get_site_url() -> str:
    """Determine site URL for OAuth redirect (Streamlit Secrets / ENV / default)."""
    url = os.getenv("SITE_URL")
    if not url:
        try:
            import streamlit as st
            url = st.secrets.get("SITE_URL")
        except Exception:
            pass
    if url:
        return url.rstrip("/")
    return "https://krishna-ai.streamlit.app"


def get_supabase_google_oauth_url(redirect_uri: Optional[str] = None) -> Tuple[bool, str]:
    """
    Generate the Supabase Auth Google OAuth authorization URL using PKCE.
    Binds the PKCE verifier deterministically to a unique state token and returns the authorization URL.
    """
    url, key = get_supabase_credentials()
    if not url or not key:
        return False, ""

    import urllib.parse
    target_redirect = redirect_uri or get_site_url()
    state_token = secrets.token_urlsafe(32)
    verifier, challenge = create_oauth_pkce_challenge()
    save_pending_pkce_verifier(state_token, verifier)

    # Embed state in redirect_to AND pass state parameter for maximum compatibility
    delimiter = "&" if "?" in target_redirect else "?"
    redirect_with_state = f"{target_redirect}{delimiter}state={state_token}"

    params = {
        "provider": "google",
        "redirect_to": redirect_with_state,
        "code_challenge": challenge,
        "code_challenge_method": "s256",
        "state": state_token
    }
    encoded = urllib.parse.urlencode(params)
    oauth_url = f"{url.rstrip('/')}/auth/v1/authorize?{encoded}"
    return True, oauth_url


def exchange_supabase_oauth_code(auth_code: str, state: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Exchange authorization code for user session with Supabase Auth.
    Deterministically looks up the PKCE verifier bound to the flow's state token.
    Executes a single token exchange (no multiple trials) to prevent code burning.
    Returns (success, user_email, error_message). Never logs tokens.
    """
    url, key = get_supabase_credentials()
    if not url or not key:
        return False, None, "Supabase credentials missing"

    now = time.time()
    existing = load_json_file(OAUTH_PKCE_FILE)
    if not isinstance(existing, dict):
        existing = {}

    target_verifier = None
    if state and state in existing:
        entry = existing.pop(state)
        if now - float(entry.get("created_at", 0)) < 900:
            target_verifier = entry.get("verifier")
        save_json_file(OAUTH_PKCE_FILE, existing)
    elif not state and len(existing) == 1:
        # Fallback if only one single pending flow exists
        only_state = next(iter(existing))
        entry = existing.pop(only_state)
        if now - float(entry.get("created_at", 0)) < 900:
            target_verifier = entry.get("verifier")
        save_json_file(OAUTH_PKCE_FILE, existing)

    if not target_verifier:
        logger.error(f"No valid PKCE verifier found for OAuth flow (state={state}).")
        return False, None, "Authentication session expired or invalid. Please click Continue with Google again."

    target_url = f"{url.rstrip('/')}/auth/v1/token?grant_type=pkce"
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json"
    }
    payload = {
        "auth_code": auth_code,
        "code_verifier": target_verifier
    }

    try:
        res = requests.post(target_url, headers=headers, json=payload, timeout=10)
        if res.status_code == 200:
            data = res.json()
            user_info = data.get("user") or {}
            user_email = user_info.get("email") or user_info.get("user_metadata", {}).get("email")
            if user_email:
                cleaned_email = user_email.strip().lower()
                _supabase_request("POST", "users", data={"email": cleaned_email}, params={"on_conflict": "email"})
                return True, cleaned_email, None
            else:
                return False, None, "No email returned by authentication provider."
        else:
            err_body = res.json() if res.content else {}
            err_msg = err_body.get("error_description") or err_body.get("msg") or f"Status {res.status_code}"
            logger.error(f"Supabase Auth exchange rejected ({res.status_code}): {err_msg}")
            return False, None, f"Authentication failed: {err_msg}"
    except Exception as e:
        logger.error(f"OAuth code exchange network error: {e}")
        return False, None, "Network error during authentication. Please try again."


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


# ─────────────────────────────────────────────
# V2 LONG-TERM MEMORY STORAGE INTERFACE
# ─────────────────────────────────────────────
MEMORY_CATEGORIES = {
    "profile", "preference", "goal", "career", "education",
    "relationship", "habit", "interest", "ongoing_context", "other"
}


def get_json_memory_path(email: str) -> str:
    """Return local path for user memory JSON file."""
    return os.path.join(DATA_DIR, f"{_safe_filename(email)}_memory.json")


def load_user_memories(email: str) -> List[Dict[str, Any]]:
    """
    Load structured long-term memories for a specific user email.
    Enforces strict authorization: users can ONLY access their own memories.
    Auto-migrates legacy string-list JSON formats with a non-destructive backup.
    """
    cleaned_email = email.strip().lower()
    if not cleaned_email:
        return []

    if is_supabase_enabled():
        ok, res = _supabase_request(
            "GET", "memories",
            params={
                "user_email": f"eq.{cleaned_email}",
                "select": "id,user_email,memory_text,category,importance,created_at,updated_at",
                "order": "importance.desc,updated_at.desc"
            }
        )
        if ok and isinstance(res, list):
            return res
        else:
            logger.info("Supabase memories fetch returned empty or failed; falling back to JSON storage.")

    # Local JSON Fallback with Non-Destructive Legacy Migration
    path = get_json_memory_path(cleaned_email)
    if not os.path.exists(path):
        return []

    loaded = load_json_file(path)
    if not loaded:
        return []

    # Check for legacy string-list format: ["User is a student...", ...]
    if isinstance(loaded, list) and len(loaded) > 0 and isinstance(loaded[0], str):
        logger.info(f"Migrating legacy memory list format for {cleaned_email} non-destructively.")
        backup_path = path + ".legacy_backup"
        if not os.path.exists(backup_path):
            save_json_file(backup_path, loaded)

        structured_memories = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for idx, item_str in enumerate(loaded):
            if isinstance(item_str, str) and item_str.strip():
                structured_memories.append({
                    "id": f"legacy_{idx}_{int(time.time())}",
                    "user_email": cleaned_email,
                    "memory_text": item_str.strip(),
                    "category": "profile",
                    "importance": 5,
                    "created_at": now_iso,
                    "updated_at": now_iso
                })
        save_json_file(path, structured_memories)
        return structured_memories

    if isinstance(loaded, list):
        valid_memories = []
        for m in loaded:
            if isinstance(m, dict) and m.get("memory_text"):
                valid_memories.append({
                    "id": str(m.get("id") or f"mem_{int(time.time()*1000)}"),
                    "user_email": cleaned_email,
                    "memory_text": str(m.get("memory_text", "")).strip(),
                    "category": m.get("category") if m.get("category") in MEMORY_CATEGORIES else "other",
                    "importance": int(m.get("importance", 5)),
                    "created_at": m.get("created_at") or datetime.now(timezone.utc).isoformat(),
                    "updated_at": m.get("updated_at") or datetime.now(timezone.utc).isoformat()
                })
        return valid_memories

    return []


def save_user_memory(
    email: str,
    memory_text: str,
    category: str = "other",
    importance: int = 5,
    memory_id: Optional[str] = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Save or upsert a structured memory for a user.
    """
    cleaned_email = email.strip().lower()
    clean_text = memory_text.strip()
    if not cleaned_email or not clean_text:
        return False, {}

    cat = category if category in MEMORY_CATEGORIES else "other"
    imp = max(1, min(10, int(importance)))
    now_iso = datetime.now(timezone.utc).isoformat()
    mem_id = memory_id or f"mem_{int(time.time()*1000)}"

    memory_record = {
        "id": mem_id,
        "user_email": cleaned_email,
        "memory_text": clean_text,
        "category": cat,
        "importance": imp,
        "created_at": now_iso,
        "updated_at": now_iso
    }

    # Save to local JSON
    path = get_json_memory_path(cleaned_email)
    current_memories = load_user_memories(cleaned_email)

    updated = False
    for i, m in enumerate(current_memories):
        if m.get("id") == mem_id:
            memory_record["created_at"] = m.get("created_at", now_iso)
            current_memories[i] = memory_record
            updated = True
            break
    if not updated:
        current_memories.append(memory_record)

    save_json_file(path, current_memories)

    # Sync to Supabase
    if is_supabase_enabled():
        try:
            _supabase_request("POST", "users", data={"email": cleaned_email}, params={"on_conflict": "email"})
            _supabase_request("POST", "memories", data=memory_record, params={"on_conflict": "id"})
        except Exception as e:
            logger.error(f"Error syncing memory to Supabase: {e}")

    return True, memory_record


def update_user_memory(
    email: str,
    memory_id: str,
    memory_text: str,
    category: Optional[str] = None,
    importance: Optional[int] = None
) -> bool:
    """
    Update an existing memory verified by user_email and memory_id.
    """
    cleaned_email = email.strip().lower()
    if not cleaned_email or not memory_id or not memory_text:
        return False

    current_memories = load_user_memories(cleaned_email)
    target = None
    for m in current_memories:
        if m.get("id") == memory_id and m.get("user_email") == cleaned_email:
            target = m
            break

    if not target:
        return False

    cat = category if (category and category in MEMORY_CATEGORIES) else target.get("category", "other")
    imp = max(1, min(10, int(importance))) if importance is not None else target.get("importance", 5)

    ok, _ = save_user_memory(
        email=cleaned_email,
        memory_text=memory_text,
        category=cat,
        importance=imp,
        memory_id=memory_id
    )
    return ok


def delete_user_memory(email: str, memory_id: str) -> bool:
    """
    Delete a single memory verified by user_email and memory_id.
    """
    cleaned_email = email.strip().lower()
    if not cleaned_email or not memory_id:
        return False

    path = get_json_memory_path(cleaned_email)
    current_memories = load_user_memories(cleaned_email)
    filtered = [m for m in current_memories if m.get("id") != memory_id]
    save_json_file(path, filtered)

    if is_supabase_enabled():
        try:
            _supabase_request("DELETE", "memories", params={"id": f"eq.{memory_id}", "user_email": f"eq.{cleaned_email}"})
        except Exception as e:
            logger.error(f"Error deleting memory from Supabase: {e}")

    return True


def clear_user_memories(email: str) -> bool:
    """
    Clear all memories for a user.
    """
    cleaned_email = email.strip().lower()
    if not cleaned_email:
        return False

    path = get_json_memory_path(cleaned_email)
    save_json_file(path, [])

    if is_supabase_enabled():
        try:
            _supabase_request("DELETE", "memories", params={"user_email": f"eq.{cleaned_email}"})
        except Exception as e:
            logger.error(f"Error clearing memories from Supabase: {e}")

    return True


def search_relevant_memories(email: str, query: str, limit: int = 5) -> List[Dict[str, Any]]:
    """
    Relevance Search: Keyword token overlap + category weighting + importance scoring.
    Zero vector embeddings or external vector database dependencies (pure ₹0-cost).
    """
    cleaned_email = email.strip().lower()
    if not cleaned_email or not query:
        return []

    memories = load_user_memories(cleaned_email)
    if not memories:
        return []

    # Tokenize query
    stopwords = {
        "a", "an", "the", "is", "are", "was", "were", "and", "or", "in", "on",
        "at", "to", "for", "of", "with", "i", "my", "me", "you", "your", "what",
        "how", "why", "can", "please", "krishna", "about", "tell", "give"
    }
    query_tokens = set(re.findall(r"\b[a-zA-Z0-9_]{2,}\b", query.lower())) - stopwords

    if not query_tokens:
        # If no specific keywords, return top memories by importance
        sorted_memories = sorted(
            memories,
            key=lambda m: (m.get("importance", 5), m.get("updated_at", "")),
            reverse=True
        )
        return sorted_memories[:limit]

    scored = []
    for m in memories:
        text = m.get("memory_text", "").lower()
        category = m.get("category", "other").lower()
        mem_tokens = set(re.findall(r"\b[a-zA-Z0-9_]{2,}\b", text))

        overlap = query_tokens.intersection(mem_tokens)
        overlap_score = len(overlap) * 3.0

        category_bonus = 2.0 if any(t in category for t in query_tokens) else 0.0
        importance_weight = m.get("importance", 5) * 0.2

        total_score = overlap_score + category_bonus + importance_weight

        if overlap_score > 0 or category_bonus > 0 or m.get("importance", 5) >= 8:
            scored.append((total_score, m))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [m for _, m in scored[:limit]]

