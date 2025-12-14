#!/usr/bin/env python3
"""Clear any login restrictions for mmadairy"""

import database
import sqlite3

def clear_login_restrictions(username):
    """Clear failed login attempts and account locks"""
    conn = database.get_connection()
    c = conn.cursor()
    
    # Clear failed login attempts and unlock account
    c.execute("""
        UPDATE users 
        SET failed_login_attempts = 0, 
            locked_until = NULL 
        WHERE username = ?
    """, (username,))
    
    conn.commit()
    conn.close()
    print(f"Cleared login restrictions for {username}")

if __name__ == "__main__":
    clear_login_restrictions("mmadairy")
    
    # Verify the user details
    user = database.get_user_by_username("mmadairy")
    if user:
        print(f"\nUser details:")
        print(f"  Username: {user['username']}")
        print(f"  Email: {user['email']}")
        print(f"  Role: {user['role']}")
        print(f"  Is active: {user['is_active']}")
        print(f"  Failed attempts: {user['failed_login_attempts']}")
        print(f"  Locked until: {user['locked_until']}")
        print(f"  Must change password: {user['must_change_password']}")
        print(f"\nPassword: Gradyb0y!")
