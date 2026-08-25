"""
Krishna AI — Safe JSON to Supabase Data Migration Utility

Purpose:
Imports existing local JSON chat histories from data/ into Supabase PostgreSQL tables without destroying or modifying local JSON source files.

Requirements:
- Preserves raw JSON source files (never deletes or mutates local data).
- Validates records before import.
- Avoids duplicate records.
- Reports migration summary.

Usage:
  python migrate_json_to_supabase.py
"""

import json
import logging
import os
import sys
from dotenv import load_dotenv
from database import is_supabase_enabled, save_user_chats, load_json_file, DATA_DIR

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("migration")


def run_migration():
    print("=" * 60)
    print("Krishna AI — Safe JSON to Supabase Data Migration Tool")
    print("=" * 60)

    if not is_supabase_enabled():
        print("\n❌ ERROR: Supabase is not configured.")
        print("Please set SUPABASE_URL and SUPABASE_KEY in your environment or secrets.")
        print("Migration aborted safely without modifying local data.")
        sys.exit(1)

    print("\n✅ Supabase credentials detected.")
    print(f"Scanning directory: {os.path.abspath(DATA_DIR)}...\n")

    if not os.path.exists(DATA_DIR):
        print("No data/ directory found. Nothing to migrate.")
        return

    # Filter files: ignore derived backup files containing '_user.local'
    files = [f for f in os.listdir(DATA_DIR) if f.endswith("_chats.json") and "_user.local" not in f]
    if not files:
        print("No original _chats.json files found in data/ directory.")
        return

    total_files = len(files)
    migrated_users = 0
    migrated_chats = 0
    migrated_msgs = 0
    errors = 0

    for filename in files:
        filepath = os.path.join(DATA_DIR, filename)
        
        # Derive email from filename (e.g. usera_gmail.com_chats.json -> usera@gmail.com)
        raw_prefix = filename.replace("_chats.json", "")
        import re
        email_guess = re.sub(r'^(.+)_([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})$', r'\1@\2', raw_prefix)
        if "@" not in email_guess:
            email_guess = f"{raw_prefix}@user.local"

        data = load_json_file(filepath)
        if not isinstance(data, dict):
            logger.warning(f"Skipping corrupt or empty file: {filename}")
            errors += 1
            continue

        print(f"Processing {filename} (derived user: {email_guess})...")
        user_chats_count = 0
        user_msgs_count = 0

        for title, msgs in data.items():
            if isinstance(msgs, list) and msgs:
                user_chats_count += 1
                user_msgs_count += len(msgs)

        if user_chats_count > 0:
            ok = save_user_chats(email_guess, data)
            if ok:
                migrated_users += 1
                migrated_chats += user_chats_count
                migrated_msgs += user_msgs_count
                print(f"  └─ Successfully migrated {user_chats_count} conversation(s), {user_msgs_count} message(s).")
            else:
                print(f"  └─ ❌ Failed to migrate {filename}.")
                errors += 1

    print("\n" + "=" * 60)
    print("MIGRATION SUMMARY")
    print("=" * 60)
    print(f"Total JSON Files Scanned: {total_files}")
    print(f"Migrated Users:           {migrated_users}")
    print(f"Migrated Conversations:   {migrated_chats}")
    print(f"Migrated Messages:        {migrated_msgs}")
    print(f"Errors Encountered:       {errors}")
    print("\n✅ All source JSON files in data/ remain intact and untouched.")
    print("=" * 60)


if __name__ == "__main__":
    run_migration()
