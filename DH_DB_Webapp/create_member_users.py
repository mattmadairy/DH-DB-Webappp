#!/usr/bin/env python3
"""
Script to create user accounts for members in the database.
Creates users with default password "password" for members who don't already have accounts.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from werkzeug.security import generate_password_hash
from database import get_all_members, get_user_by_email, create_user, get_connection

def create_users_for_members():
    """Create user accounts for members who don't already have them."""

    print("🔍 Getting all members from database...")
    members = get_all_members()

    if not members:
        print("❌ No members found in database.")
        return

    print(f"📊 Found {len(members)} members.")

    created_count = 0
    skipped_count = 0

    for member in members:
        member_id = member['id']
        first_name = member['first_name']
        last_name = member['last_name']
        email = member['email']

        # Skip members without email
        if not email:
            print(f"⚠️  Skipping member {first_name} {last_name} (ID: {member_id}) - no email address")
            skipped_count += 1
            continue

        # Check if user already exists
        existing_user = get_user_by_email(email)
        if existing_user:
            print(f"⏭️  Skipping {first_name} {last_name} ({email}) - user already exists")
            skipped_count += 1
            continue

        # Use email as username
        username = email
        full_name = f"{first_name} {last_name}"

        # Hash the default password
        password_hash = generate_password_hash("password")

        # Create the user
        try:
            user_id = create_user(
                username=username,
                password_hash=password_hash,
                email=email,
                name=full_name,
                role='User'
            )

            if user_id:
                print(f"✅ Created user: {username} ({email}) - User ID: {user_id}")
                created_count += 1
            else:
                print(f"❌ Failed to create user for {first_name} {last_name} ({email}) - possible duplicate username")
                skipped_count += 1

        except Exception as e:
            print(f"❌ Error creating user for {first_name} {last_name} ({email}): {str(e)}")
            skipped_count += 1

    print("\n📈 Summary:")
    print(f"   ✅ Users created: {created_count}")
    print(f"   ⏭️  Users skipped: {skipped_count}")
    print(f"   📊 Total members processed: {len(members)}")

    if created_count > 0:
        print("\n🔐 IMPORTANT: All new users have the default password 'password'")
        print("   They will be required to change their password on first login.")
if __name__ == "__main__":
    print("🚀 Starting user creation script for members...")
    print("=" * 50)

    create_users_for_members()

    print("=" * 50)
    print("✨ Script completed!")