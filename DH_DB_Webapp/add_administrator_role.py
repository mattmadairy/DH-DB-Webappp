"""
Script to ensure BDFL user exists with a known password.
This is safe to run multiple times - it will create or update the user.
"""
import sqlite3
from werkzeug.security import generate_password_hash
from datetime import datetime

DB_NAME = 'members.db'
BDFL_USERNAME = 'mmadairy'
BDFL_PASSWORD = 'Gradyb0y'  # Change this to your desired password
BDFL_EMAIL = 'mmadairy@example.com'  # Change this to actual email
BDFL_NAME = 'Matthew Madairy'  # Change this to actual name

def ensure_bdfl_user():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Check if BDFL user exists
    cursor.execute("SELECT id, role FROM users WHERE username = ?", (BDFL_USERNAME,))
    existing_user = cursor.fetchone()
    
    password_hash = generate_password_hash(BDFL_PASSWORD)
    
    if existing_user:
        user_id, current_role = existing_user
        print(f"User '{BDFL_USERNAME}' already exists (ID: {user_id}, Role: {current_role})")
        
        # Update role to BDFL and reset password
        cursor.execute("""
            UPDATE users 
            SET role = 'BDFL', 
                password_hash = ?,
                must_change_password = 0,
                is_active = 1
            WHERE username = ?
        """, (password_hash, BDFL_USERNAME))
        conn.commit()
        print(f"✓ Updated '{BDFL_USERNAME}' to BDFL role")
        print(f"✓ Password set to: {BDFL_PASSWORD}")
        print(f"✓ Account activated and password change requirement removed")
    else:
        # Create new BDFL user
        cursor.execute("""
            INSERT INTO users (username, name, password_hash, email, created_at, role, is_active, must_change_password)
            VALUES (?, ?, ?, ?, ?, 'BDFL', 1, 0)
        """, (BDFL_USERNAME, BDFL_NAME, password_hash, BDFL_EMAIL, datetime.now().isoformat()))
        conn.commit()
        user_id = cursor.lastrowid
        print(f"✓ Created new BDFL user '{BDFL_USERNAME}' (ID: {user_id})")
        print(f"✓ Password set to: {BDFL_PASSWORD}")
    
    # Show all users
    cursor.execute("SELECT id, username, role, is_active FROM users")
    users = cursor.fetchall()
    print("\n=== Current Users ===")
    for user in users:
        uid, uname, urole, uactive = user
        status = "Active" if uactive else "Inactive"
        print(f"  {uid}: {uname} - {urole} ({status})")
    
    conn.close()
    print(f"\n✓ You can now login with username: {BDFL_USERNAME} and password: {BDFL_PASSWORD}")

if __name__ == '__main__':
    ensure_bdfl_user()
