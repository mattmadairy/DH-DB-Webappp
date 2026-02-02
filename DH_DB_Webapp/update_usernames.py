#!/usr/bin/env python3
"""
Script to update existing user usernames from first.last format to email addresses.
"""

import sys
import os
import re
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import get_all_users, update_user

def is_first_last_format(username):
    """Check if username is in first.last format (not an email)"""
    # If it contains @, it's already an email
    if '@' in username:
        return False

    # Check if it matches first.last pattern (letters, dot, letters)
    pattern = r'^[a-z]+\.[a-z]+$'
    return bool(re.match(pattern, username.lower()))

def update_usernames_to_emails():
    """Update existing users from first.last format to email usernames."""

    print("🔍 Getting all users from database...")
    users = get_all_users()

    if not users:
        print("❌ No users found in database.")
        return

    print(f"📊 Found {len(users)} users.")

    updated_count = 0
    skipped_count = 0

    for user in users:
        user_id = user[0]  # id
        current_username = user[1]  # username
        name = user[2]  # name
        email = user[3]  # email
        role = user[4]  # role

        # Skip if username is already an email
        if '@' in current_username:
            print(f"⏭️  Skipping {name} ({email}) - username already an email: {current_username}")
            skipped_count += 1
            continue

        # Skip if not in first.last format
        if not is_first_last_format(current_username):
            print(f"⏭️  Skipping {name} ({email}) - username not in first.last format: {current_username}")
            skipped_count += 1
            continue

        # Skip if no email address
        if not email:
            print(f"⚠️  Skipping {name} (ID: {user_id}) - no email address")
            skipped_count += 1
            continue

        # Update username to email
        try:
            update_user(user_id, email, name, email, role)
            print(f"✅ Updated {name}: '{current_username}' → '{email}'")
            updated_count += 1

        except Exception as e:
            print(f"❌ Error updating {name} ({current_username}): {str(e)}")
            skipped_count += 1

    print("\n📈 Summary:")
    print(f"   ✅ Users updated: {updated_count}")
    print(f"   ⏭️  Users skipped: {skipped_count}")
    print(f"   📊 Total users processed: {len(users)}")

    if updated_count > 0:
        print("\n🔄 Username updates completed!")
        print("   All users can now log in with their email address.")
if __name__ == "__main__":
    print("🚀 Starting username update script...")
    print("=" * 50)

    update_usernames_to_emails()

    print("=" * 50)
    print("✨ Script completed!")