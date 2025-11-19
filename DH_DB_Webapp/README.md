# DH Member Database Web Application

A Flask-based web application for managing member information, dues, work hours, meeting attendance, and committee assignments.

## Features

- **Member Management**: Add, edit, view, and soft-delete member records
- **Dues Tracking**: Record and track membership dues payments by year
- **Work Hours**: Log and report member work hours by activity type
- **Meeting Attendance**: Track meeting attendance with status (Attended, Exempt, Absent)
- **Committees**: Manage committee memberships and assignments
- **Roles & Positions**: Track leadership positions with term dates
- **Reports**: Generate various reports including dues, work hours, and attendance
- **Recycle Bin**: Soft delete system with restore capability

## Requirements

- Python 3.8 or higher
- Flask 3.0.0+
- SQLite3 (included with Python)

## Installation

### Option 1: Quick Install

```bash
# Clone the repository
git clone https://github.com/mattmadairy/DH-DB-Webappp.git
cd DH-DB-Webappp/DH_DB_Webapp

# Install dependencies
pip install -r requirements.txt

# Initialize the database
python init_db.py

# Run the application
python app.py
```

### Option 2: Install as Package

```bash
# Clone the repository
git clone https://github.com/mattmadairy/DH-DB-Webappp.git
cd DH-DB-Webappp/DH_DB_Webapp

# Install the package
pip install .

# Initialize the database
python init_db.py

# Run the application
python app.py
```

### Option 3: Development Install

```bash
# Clone the repository
git clone https://github.com/mattmadairy/DH-DB-Webappp.git
cd DH-DB-Webappp/DH_DB_Webapp

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize the database
python init_db.py

# Run the application
python app.py
```

## Configuration

### Development Server

The app runs on `http://127.0.0.1:5000` by default.

To allow remote access (for testing only):
```python
# In app.py, change the last line to:
app.run(debug=True, host='0.0.0.0', port=5000)
```

### Production Deployment

**Important**: Never run with `debug=True` in production!

```python
# In app.py:
if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=5000)
```

Consider using a production WSGI server like Waitress or Gunicorn:

```bash
# Install Waitress
pip install waitress

# Run with Waitress
waitress-serve --host=0.0.0.0 --port=5000 app:app
```

## Database

The application uses SQLite and automatically creates the database on first run. The database file `members.db` will be created in the application directory.

### Database Schema

- **members**: Core member information
- **dues**: Payment tracking
- **work_hours**: Work hour logging
- **meeting_attendance**: Meeting attendance records
- **roles**: Leadership positions
- **committees**: Committee memberships

### Manual Database Initialization

If needed, run:
```bash
python init_db.py
```

## Usage

1. **Home Page** (`/`): View and search all active members
2. **Add Member** (`/add_member`): Create new member records
3. **Member Details** (`/member/<id>`): View complete member information
4. **Edit Member** (`/edit_member/<id>`): Edit member information
5. **Reports** (`/reports`): Access various reporting tools
6. **Recycle Bin** (`/recycle_bin`): View and restore deleted members

## Project Structure

```
DH_DB_Webapp/
├── app.py                  # Main Flask application
├── database.py             # Database functions
├── init_db.py              # Database initialization script
├── requirements.txt        # Python dependencies
├── setup.py                # Package setup file
├── README.md               # This file
├── static/                 # Static files (CSS, JS, images)
├── templates/              # HTML templates
│   ├── index.html
│   ├── member_details.html
│   ├── add_member.html
│   ├── edit_member.html
│   ├── reports.html
│   ├── dues_report.html
│   ├── work_hours_report.html
│   ├── meeting_attendance_report.html
│   ├── committees.html
│   └── recycle_bin.html
└── members.db              # SQLite database (created on first run)
```

## Deployment Options

### Local Network
- Run on a local machine and access via LAN IP address
- Configure router port forwarding for external access

### Cloud Hosting
- **PythonAnywhere**: Free tier available, easy Flask deployment
- **Render**: Free tier with auto-deploy from GitHub
- **Railway**: Modern platform with free credits
- **Heroku**: Paid plans starting at $7/month
- **DigitalOcean**: App Platform or VPS hosting
- **AWS/Azure/GCP**: Enterprise-grade cloud hosting

## Security Considerations

Before deploying to production:

1. **Remove debug mode**: Set `debug=False`
2. **Add authentication**: Implement user login system
3. **Use HTTPS**: Enable SSL/TLS encryption
4. **Secure the database**: Regular backups, access controls
5. **Environment variables**: Store sensitive configuration separately
6. **Input validation**: Already implemented, but review regularly
7. **Rate limiting**: Consider adding to prevent abuse

## Contributing

This is a private project. For issues or feature requests, contact the repository owner.

## License

[Specify your license here]

## Support

For questions or issues, please contact Matt Madairy or open an issue on GitHub.

## Version History

- **1.0.0** (2025-11-18): Initial release
  - Member management system
  - Dues tracking
  - Work hours logging
  - Meeting attendance
  - Committee management
  - Reporting tools
  - Soft delete/recycle bin
