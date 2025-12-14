#!/usr/bin/env python3
"""
Script to reset a user's password in the DH-DB-Webapp database.
Usage: python reset_password.py
"""

from werkzeug.security import generate_password_hash
import database
import sys

def reset_password(username, new_password):
    """Reset a user's password"""
    # Get the user
    user = database.get_user_by_username(username)
    
    if not user:
        print(f"Error: User '{username}' not found.")
        return False
    
    # Generate password hash
    password_hash = generate_password_hash(new_password)
    
    # Update the password
    try:
        database.update_user_password(user['id'], password_hash)
        print(f"Password for user '{username}' has been reset successfully.")
        return True
    except Exception as e:
        print(f"Error updating password: {e}")
        return False

if __name__ == "__main__":
    # Reset password for mmadairy
    username = "mmadairy"
    new_password = "Gradyb0y!"
    
    print(f"Resetting password for user: {username}")
    reset_password(username, new_password)
