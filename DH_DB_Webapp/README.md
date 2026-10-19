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

- Python 3.10 or newer
- SQLite (included with Python)
- Packages listed in `requirements.txt`

## Installation

Run these commands from `DH_DB_Webapp`:

```bash
python -m venv venv
```

Activate the environment, then install dependencies:

```bash
# Windows PowerShell
.\venv\Scripts\Activate.ps1

# Linux or macOS
source venv/bin/activate

python -m pip install -r requirements.txt
```

Copy `.env.example` to `.env` and set a unique `SECRET_KEY` and environment-specific values. Do not commit `.env` or credentials. The database tables are created automatically when the application imports `database.py`; no separate initialization script is needed.

Start the development server with:

```bash
python app.py
```

For production, configure the WSGI server to use the same virtual environment and set production environment variables. Do not use Flask's debug server in production.

## Configuration

The app reads settings from environment variables and a local `.env` file. See `.env.example` for the available settings. Keep production secrets in the WSGI configuration or environment, not in source control.

## Database

The application uses SQLite and creates its tables on first import. `members.db` is stored in the repository root, one directory above `DH_DB_Webapp`.

### Database Schema

- **members**: Core member information
- **dues**: Payment tracking
- **work_hours**: Work hour logging
- **meeting_attendance**: Meeting attendance records
- **roles**: Leadership positions
- **committees**: Committee memberships

## Usage

1. **Home Page** (`/`): View and search all active members
2. **Add Member** (`/add_member`): Create new member records
3. **Member Details** (`/member/<id>`): View complete member information
4. **Edit Member** (`/edit_member/<id>`): Edit member information
5. **Recycle Bin** (`/recycle_bin`): View and restore deleted members

## Project Structure

```
DH-DB-Webappp/
├── members.db                 # SQLite database
└── DH_DB_Webapp/
    ├── app.py                 # Flask routes and application logic
    ├── config.py              # Environment-based configuration
    ├── database.py            # SQLite schema and data access
    ├── requirements.txt       # Runtime dependencies
    ├── requirements-dev.txt   # Development dependencies
    ├── document_descriptions.json
    ├── static/
    └── templates/
```

The SQLite database path is calculated by `database.py` relative to the repository root. Back it up before deploying or changing database code.

## Production Deployment

Configure the WSGI server to import `app` from `DH_DB_Webapp/app.py`, use the project's virtual environment, and set production environment variables. Install dependencies with `python -m pip install -r DH_DB_Webapp/requirements.txt`, then reload the web app. Do not overwrite the live `members.db` with a development copy.

## Security Considerations

Before deploying to production:

1. Set a unique `SECRET_KEY` and keep it private.
2. Use HTTPS and secure cookies in production.
3. Back up the SQLite database before deploying changes.
4. Keep credentials and `.env` files out of source control.
5. Use the configured production WSGI server and disable debug mode.

## Contributing

This is a private project. For issues or feature requests, contact the repository owner.

## License

MIT; see [`LICENSE`](LICENSE).

## Support

For questions or issues, please contact Matt Madairy or open an issue on GitHub.

