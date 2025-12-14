#!/usr/bin/env python3
"""Test if the password works"""

from werkzeug.security import check_password_hash
import database

user = database.get_user_by_username('mmadairy')
if user:
    password = 'Gradyb0y!'
    matches = check_password_hash(user['password_hash'], password)
    print(f"Password matches: {matches}")
    print(f"Password hash: {user['password_hash']}")
else:
    print("User not found")
