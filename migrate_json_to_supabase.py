"""
Krishna AI — Production-Grade Safe & Idempotent Supabase Migration Utility

Purpose:
Imports existing local JSON chat histories from data/ into Supabase PostgreSQL tables safely and idempotently.

Safety Guarantees:
- Never deletes or modifies local JSON source files.
- Never creates temporary _user.local backup files.
- Never duplicates users, conversations, or messages on repeated runs.
- Accurately reports newly inserted vs existing/skipped records.
- Returns non-zero exit code if genuine API or network errors occur.

Usage:
  python migrate_json_to_supabase.py
"""

import json
import logging
import os
import re
import sys
from dotenv import load_dotenv
from database import is_supabase_enabled, _supabase_request, load_json_file, DATA_DIR

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("migration")


def run_migration():
    print("=" * 65)
    print("KRISHNA AI — PRODUCTION-GRADE IDEMPOTENT DATA MIGRATION TOOL")
    print("=" * 65)

    if not is_supabase_enabled():
        print("\n[ERROR] Supabase is not configured.")
        print("Please set SUPABASE_URL and SUPABASE_KEY in your environment or secrets.")
        print("Migration aborted safely without modifying local data.")
        sys.exit(1)

    print("\n[OK] Supabase credentials detected.")
    print(f"Scanning directory: {os.path.abspath(DATA_DIR)}...\n")

    if not os.path.exists(DATA_DIR):
        print("No data/ directory found. Nothing to migrate.")
        return

    # Filter files: ignore derived backup files containing '_user.local'
    files = [f for f in os.listdir(DATA_DIR) if f.endswith("_chats.json") and "_user.local" not in f]
    if not files:
        print("No original _chats.json files found in data/ directory.")
        return

    stats = {
        "files_scanned": len(files),
        "users_new": 0,
        "users_existing": 0,
        "conversations_new": 0,
        "conversations_existing": 0,
        "messages_new": 0,
        "messages_existing": 0,
        "errors": 0
    }

    for filename in files:
        filepath = os.path.join(DATA_DIR, filename)

        # Derive user email from filename (e.g. usera_gmail.com_chats.json -> usera@gmail.com)
        raw_prefix = filename.replace("_chats.json", "")
        email_guess = re.sub(r'^(.+)_([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})$', r'\1@\2', raw_prefix)
        if "@" not in email_guess:
            print(f"[WARN] Skipping unrecognized filename format: {filename}")
            continue

        cleaned_email = email_guess.strip().lower()
        data = load_json_file(filepath)
        if not isinstance(data, dict):
            logger.warning(f"Skipping corrupt or empty file: {filename}")
            stats["errors"] += 1
            continue

        print(f"Processing {filename} -> User: {cleaned_email}")

        # ── 1. USER HANDLING ──
        ok_u, res_u = _supabase_request("GET", "users", params={"email": f"eq.{cleaned_email}", "select": "email"})
        if ok_u and isinstance(res_u, list) and len(res_u) > 0:
            stats["users_existing"] += 1
        else:
            ok_ins, res_ins = _supabase_request("POST", "users", data={"email": cleaned_email})
            if ok_ins:
                stats["users_new"] += 1
            else:
                logger.error(f"Failed to create user {cleaned_email}: {res_ins}")
                stats["errors"] += 1
                continue

        # ── 2. CONVERSATION & MESSAGE HANDLING ──
        for title, msgs in data.items():
            if not isinstance(msgs, list) or not msgs:
                continue

            conv_id = None
            ok_c, res_c = _supabase_request("GET", "conversations", params={"user_email": f"eq.{cleaned_email}", "title": f"eq.{title}", "select": "id,title"})
            
            if ok_c and isinstance(res_c, list) and len(res_c) > 0:
                conv_id = res_c[0].get("id")
                stats["conversations_existing"] += 1
            else:
                ok_cin, res_cin = _supabase_request("POST", "conversations", data={"user_email": cleaned_email, "title": title})
                if ok_cin and isinstance(res_cin, list) and len(res_cin) > 0:
                    conv_id = res_cin[0].get("id")
                    stats["conversations_new"] += 1
                else:
                    logger.error(f"Failed to create conversation '{title}' for {cleaned_email}: {res_cin}")
                    stats["errors"] += 1
                    continue

            if not conv_id:
                continue

            # Fetch existing messages for this conversation
            ok_m, res_m = _supabase_request("GET", "messages", params={"conversation_id": f"eq.{conv_id}", "user_email": f"eq.{cleaned_email}", "select": "role,content,timestamp"})
            
            existing_fingerprints = set()
            if ok_m and isinstance(res_m, list):
                for em in res_m:
                    existing_fingerprints.add((em.get("role", "user"), em.get("content", ""), em.get("timestamp", "")))

            new_message_batch = []
            for m in msgs:
                fp = (m.get("role", "user"), m.get("content", ""), m.get("timestamp", ""))
                if fp in existing_fingerprints:
                    stats["messages_existing"] += 1
                else:
                    new_message_batch.append({
                        "conversation_id": conv_id,
                        "user_email": cleaned_email,
                        "role": m.get("role", "user"),
                        "content": m.get("content", ""),
                        "timestamp": m.get("timestamp", ""),
                        "is_error": m.get("is_error", False)
                    })
                    existing_fingerprints.add(fp)

            if new_message_batch:
                ok_min, res_min = _supabase_request("POST", "messages", data=new_message_batch)
                if ok_min:
                    stats["messages_new"] += len(new_message_batch)
                    print(f"  + Inserted {len(new_message_batch)} new message(s) into '{title}'")
                else:
                    logger.error(f"Failed to insert messages for '{title}': {res_min}")
                    stats["errors"] += len(new_message_batch)
            else:
                print(f"  . Conversation '{title}' up-to-date (all messages already exist)")

    print("\n" + "=" * 65)
    print("MIGRATION SUMMARY")
    print("=" * 65)
    print(f"Files scanned:            {stats['files_scanned']}")
    print("\nUsers:")
    print(f"  Newly migrated:         {stats['users_new']}")
    print(f"  Already existed:        {stats['users_existing']}")
    print("\nConversations:")
    print(f"  Newly migrated:         {stats['conversations_new']}")
    print(f"  Already existed:        {stats['conversations_existing']}")
    print("\nMessages:")
    print(f"  Newly migrated:         {stats['messages_new']}")
    print(f"  Already existed/skipped:{stats['messages_existing']}")
    print(f"\nErrors Encountered:       {stats['errors']}")
    print("Source JSON Files Modified:0")
    print("=" * 65)

    if stats["errors"] > 0:
        print("\n[ERROR] Migration completed with errors. See logs above.")
        sys.exit(1)
    else:
        print("\n[SUCCESS] Migration completed successfully with zero errors.")


if __name__ == "__main__":
    run_migration()
