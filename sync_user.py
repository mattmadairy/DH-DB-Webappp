#!/usr/bin/env python3
"""
Copy user from DH_DB_Webapp/members.db to the root members.db
"""

import sqlite3
import shutil
import os

source_db = '/workspaces/DH-DB-Webappp/DH_DB_Webapp/members.db'
target_db = '/workspaces/DH-DB-Webappp/members.db'

print(f"Source DB: {source_db}")
print(f"Target DB: {target_db}")

# Get user from source
conn_source = sqlite3.connect(source_db)
conn_source.row_factory = sqlite3.Row
c_source = conn_source.cursor()
c_source.execute("SELECT * FROM users WHERE username='mmadairy'")
user = c_source.fetchone()
conn_source.close()

if not user:
    print("ERROR: User mmadairy not found in source database!")
    exit(1)

user_dict = dict(user)
print(f"\nUser found in source:")
print(f"  Username: {user_dict['username']}")
print(f"  Email: {user_dict['email']}")
print(f"  Role: {user_dict['role']}")

# Check if target database exists
if not os.path.exists(target_db):
    print(f"\nTarget database doesn't exist. Copying entire database...")
    shutil.copy2(source_db, target_db)
    print("Database copied successfully!")
else:
    # Update or insert into target
    conn_target = sqlite3.connect(target_db)
    c_target = conn_target.cursor()
    
    # Check if user exists in target
    c_target.execute("SELECT id FROM users WHERE username='mmadairy'")
    existing = c_target.fetchone()
    
    if existing:
        print(f"\nUpdating user in target database...")
        c_target.execute("""
            UPDATE users 
            SET password_hash=?, email=?, role=?, is_active=?, 
                must_change_password=?, failed_login_attempts=?, 
                locked_until=?, name=?
            WHERE username=?
        """, (
            user_dict['password_hash'],
            user_dict['email'],
            user_dict['role'],
            user_dict['is_active'],
            user_dict['must_change_password'],
            user_dict['failed_login_attempts'],
            user_dict['locked_until'],
            user_dict['name'],
            user_dict['username']
        ))
    else:
        print(f"\nInserting user into target database...")
        c_target.execute("""
            INSERT INTO users (
                username, name, password_hash, email, created_at, is_active, 
                role, must_change_password, failed_login_attempts, locked_until, 
                last_login, last_password_change
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_dict['username'],
            user_dict['name'],
            user_dict['password_hash'],
            user_dict['email'],
            user_dict['created_at'],
            user_dict['is_active'],
            user_dict['role'],
            user_dict['must_change_password'],
            user_dict['failed_login_attempts'],
            user_dict['locked_until'],
            user_dict['last_login'],
            user_dict['last_password_change']
        ))
    
    conn_target.commit()
    conn_target.close()
    print("User synchronized successfully!")

# Verify in target
conn_verify = sqlite3.connect(target_db)
conn_verify.row_factory = sqlite3.Row
c_verify = conn_verify.cursor()
c_verify.execute("SELECT * FROM users WHERE username='mmadairy'")
verified_user = c_verify.fetchone()
conn_verify.close()

if verified_user:
    from werkzeug.security import check_password_hash
    password = 'Gradyb0y!'
    matches = check_password_hash(verified_user['password_hash'], password)
    print(f"\n✓ Verification:")
    print(f"  User exists in target: YES")
    print(f"  Password matches: {matches}")
    print(f"\nLogin credentials:")
    print(f"  Username: mmadairy")
    print(f"  Password: Gradyb0y!")
else:
    print("\n✗ ERROR: User not found in target after sync!")
