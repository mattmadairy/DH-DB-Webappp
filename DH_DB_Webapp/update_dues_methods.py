"""
Script to update dues payment methods in the database.
Changes 'Online' and 'Card' entries to 'Stripe'.
"""

import database

def update_dues_methods():
    """Update dues payment methods from 'Online' and 'Card' to 'Stripe'"""
    
    # Get database connection
    conn = database.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Update 'Online' to 'Stripe'
        cursor.execute("UPDATE dues SET method = 'Stripe' WHERE method = 'Online'")
        online_count = cursor.rowcount
        
        # Update 'Card' to 'Stripe'
        cursor.execute("UPDATE dues SET method = 'Stripe' WHERE method = 'Card'")
        card_count = cursor.rowcount
        
        # Commit the changes
        conn.commit()
        
        print(f"Updated {online_count} 'Online' entries to 'Stripe'")
        print(f"Updated {card_count} 'Card' entries to 'Stripe'")
        print(f"Total updated: {online_count + card_count}")
        
    except Exception as e:
        conn.rollback()
        print(f"Error updating dues methods: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    print("Starting dues method update...")
    update_dues_methods()
    print("Update complete!")
