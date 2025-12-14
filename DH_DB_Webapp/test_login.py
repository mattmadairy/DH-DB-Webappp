#!/usr/bin/env python3
"""
Comprehensive test of the login process for mmadairy
"""

from werkzeug.security import check_password_hash, generate_password_hash
import database
import datetime

username = "mmadairy"
password = "Gradyb0y!"

print("=" * 60)
print("COMPREHENSIVE LOGIN TEST")
print("=" * 60)

# Get user
user_data = database.get_user_by_username(username)

if not user_data:
    print(f"ERROR: User '{username}' not found!")
    exit(1)

print(f"\n1. USER FOUND")
print(f"   Username: {user_data['username']}")
print(f"   Email: {user_data['email']}")
print(f"   Role: {user_data['role']}")

print(f"\n2. ACCOUNT STATUS")
print(f"   Is Active: {user_data['is_active']} {'✓' if user_data['is_active'] else '✗'}")
print(f"   Failed Login Attempts: {user_data['failed_login_attempts']}")
print(f"   Locked Until: {user_data['locked_until']}")
print(f"   Must Change Password: {user_data['must_change_password']}")

# Check if account is locked
is_locked, locked_until = database.is_account_locked(username)
print(f"\n3. ACCOUNT LOCK CHECK")
print(f"   Is Locked: {is_locked} {'✗ PROBLEM!' if is_locked else '✓'}")
if is_locked:
    remaining = (locked_until - datetime.datetime.now()).total_seconds() / 60
    print(f"   Locked Until: {locked_until}")
    print(f"   Remaining: {int(remaining)} minutes")

# Check password
password_matches = check_password_hash(user_data['password_hash'], password)
print(f"\n4. PASSWORD VERIFICATION")
print(f"   Password: {password}")
print(f"   Password Matches: {password_matches} {'✓' if password_matches else '✗ PROBLEM!'}")

print(f"\n5. STORED PASSWORD HASH")
print(f"   Hash: {user_data['password_hash'][:80]}...")

# Test with the exact same method as the login route
print(f"\n6. LOGIN ROUTE SIMULATION")
if user_data and user_data['is_active']:
    print(f"   ✓ User exists and is active")
    
    is_locked, locked_until = database.is_account_locked(username)
    if is_locked:
        print(f"   ✗ PROBLEM: Account is locked!")
    else:
        print(f"   ✓ Account is not locked")
    
    if check_password_hash(user_data['password_hash'], password):
        print(f"   ✓ Password check passed - LOGIN SHOULD WORK!")
    else:
        print(f"   ✗ PROBLEM: Password check failed!")
else:
    print(f"   ✗ PROBLEM: User doesn't exist or is not active")

print("\n" + "=" * 60)
print("RECOMMENDATION:")
if is_locked:
    print("  Account is LOCKED. Unlock it first.")
elif not password_matches:
    print("  Password is WRONG. Reset it again.")
elif not user_data['is_active']:
    print("  Account is INACTIVE. Activate it.")
else:
    print("  Everything looks CORRECT. Login should work!")
    print(f"  Try: Username='{username}' Password='{password}'")
print("=" * 60)
