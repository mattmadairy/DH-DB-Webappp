import database

users = database.get_all_users()
print('Users:')
for u in users:
    print(f'{u["username"]}: {u["email"]} ({u["role"]})')

print('\nMembers with M in first name:')
members = database.get_all_members()
for m in members:
    if m['first_name'].startswith('M'):
        print(f'{m["first_name"]} {m["last_name"]}: {m["email"]} / {m["email2"]}')

print('\nAll members (first 10):')
for m in members[:10]:
    print(f'{m["first_name"]} {m["last_name"]}: {m["email"]} / {m["email2"]}')