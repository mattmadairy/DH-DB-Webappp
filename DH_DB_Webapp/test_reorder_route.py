#!/usr/bin/env python3
"""
Test the reorder route directly
"""
import requests
import json

# This would need to be run with a proper session/cookies
# For now, let's just check if we can access the route structure

print("Testing reorder route structure...")

# Check the document_descriptions.json file
DESCRIPTIONS_FILE = 'document_descriptions.json'

try:
    with open(DESCRIPTIONS_FILE, 'r') as f:
        config = json.load(f)
    print(f"Current config: {config}")
except Exception as e:
    print(f"Error reading config: {e}")

print("To test the reorder functionality:")
print("1. Open browser to http://127.0.0.1:5000/member_documents")
print("2. Login as admin")
print("3. Try clicking the up/down buttons")
print("4. Check browser console for JavaScript errors")
print("5. Try clicking 'Save Document Order'")
print("6. Check server console for reorder request logs")