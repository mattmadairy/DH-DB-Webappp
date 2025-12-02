import sqlite3
import re

DB_NAME = "members.db"

def format_phone_number(phone):
    """Format phone number to (XXX) XXX-XXXX"""
    if not phone:
        return phone
    
    # Remove all non-digit characters
    digits = re.sub(r'\D', '', phone)
    
    # Only format if we have exactly 10 digits
    if len(digits) == 10:
        return f"({digits[0:3]}) {digits[3:6]}-{digits[6:10]}"
    
    # Return original if not 10 digits
    return phone

def update_all_phone_numbers():
    """Update all phone numbers in the database to formatted style"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Get all members with their phone numbers
    c.execute("SELECT id, phone, phone2 FROM members")
    members = c.fetchall()
    
    updated_count = 0
    
    for member in members:
        member_id = member['id']
        phone = member['phone']
        phone2 = member['phone2']
        
        # Format phone numbers
        formatted_phone = format_phone_number(phone)
        formatted_phone2 = format_phone_number(phone2)
        
        # Update if changed
        if formatted_phone != phone or formatted_phone2 != phone2:
            c.execute("UPDATE members SET phone=?, phone2=? WHERE id=?", 
                     (formatted_phone, formatted_phone2, member_id))
            updated_count += 1
            print(f"Updated member ID {member_id}:")
            if formatted_phone != phone:
                print(f"  Phone: {phone} -> {formatted_phone}")
            if formatted_phone2 != phone2:
                print(f"  Phone2: {phone2} -> {formatted_phone2}")
    
    conn.commit()
    conn.close()
    
    print(f"\nTotal members updated: {updated_count}")

if __name__ == "__main__":
    print("Formatting phone numbers in database...")
    print("=" * 50)
    update_all_phone_numbers()
    print("=" * 50)
    print("Done!")
