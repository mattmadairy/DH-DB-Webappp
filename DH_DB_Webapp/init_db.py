import sqlite3
import os

DB_NAME = "members.db"

def init_database():
    """Initialize the database with all required tables."""
    
    # Remove existing database if you want a fresh start (optional)
    # if os.path.exists(DB_NAME):
    #     os.remove(DB_NAME)
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Create members table
    c.execute("""
        CREATE TABLE IF NOT EXISTS members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            badge_number TEXT,
            membership_type TEXT,
            first_name TEXT NOT NULL,
            middle_name TEXT,
            last_name TEXT NOT NULL,
            suffix TEXT,
            nickname TEXT,
            dob TEXT,
            email TEXT,
            email2 TEXT,
            phone TEXT,
            phone2 TEXT,
            address TEXT,
            city TEXT,
            state TEXT,
            zip TEXT,
            join_date TEXT,
            sponsor TEXT,
            card_internal TEXT,
            card_external TEXT,
            deleted INTEGER DEFAULT 0,
            deleted_on TEXT
        )
    """)
    
    # Create dues table
    c.execute("""
        CREATE TABLE IF NOT EXISTS dues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER NOT NULL,
            payment_date TEXT NOT NULL,
            amount REAL NOT NULL,
            year TEXT NOT NULL,
            method TEXT,
            notes TEXT,
            FOREIGN KEY (member_id) REFERENCES members(id)
        )
    """)
    
    # Create work_hours table
    c.execute("""
        CREATE TABLE IF NOT EXISTS work_hours (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            activity TEXT NOT NULL,
            hours REAL NOT NULL,
            notes TEXT,
            FOREIGN KEY (member_id) REFERENCES members(id)
        )
    """)
    
    # Create meeting_attendance table
    c.execute("""
        CREATE TABLE IF NOT EXISTS meeting_attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER NOT NULL,
            meeting_date TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY (member_id) REFERENCES members(id)
        )
    """)
    
    # Create roles table
    c.execute("""
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER NOT NULL,
            position TEXT,
            term_start TEXT,
            term_end TEXT,
            FOREIGN KEY (member_id) REFERENCES members(id)
        )
    """)
    
    # Create committees table
    c.execute("""
        CREATE TABLE IF NOT EXISTS committees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER NOT NULL,
            executive_committee INTEGER DEFAULT 0,
            gun_bingo_social_events INTEGER DEFAULT 0,
            building_and_grounds INTEGER DEFAULT 0,
            fundraising INTEGER DEFAULT 0,
            membership INTEGER DEFAULT 0,
            FOREIGN KEY (member_id) REFERENCES members(id)
        )
    """)
    
    conn.commit()
    conn.close()
    
    print(f"Database '{DB_NAME}' initialized successfully!")
    print("All tables created.")

if __name__ == "__main__":
    init_database()
