# Installation Guide - DH Member Database

## Quick Start (5 minutes)

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Git (optional, for cloning)

### Step-by-Step Installation

#### 1. Get the Code

**Option A: Download ZIP**
1. Download the repository as ZIP
2. Extract to your desired location
3. Open terminal/command prompt in the extracted folder

**Option B: Clone with Git**
```bash
git clone https://github.com/mattmadairy/DH-DB-Webappp.git
cd DH-DB-Webappp/DH_DB_Webapp
```

#### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

Or install individually:
```bash
pip install Flask==3.0.0
pip install Werkzeug==3.0.1
```

#### 3. Initialize the Database

```bash
python init_db.py
```

You should see: `Database 'members.db' initialized successfully!`

#### 4. Run the Application

```bash
python app.py
```

You should see:
```
 * Running on http://127.0.0.1:5000
```

#### 5. Open in Browser

Navigate to: `http://127.0.0.1:5000`

---

## Detailed Installation Options

### Option 1: Virtual Environment (Recommended)

Using a virtual environment keeps dependencies isolated:

**Windows:**
```bash
# Create virtual environment
python -m venv venv

# Activate it
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python init_db.py

# Run app
python app.py
```

**Linux/Mac:**
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python init_db.py

# Run app
python app.py
```

### Option 2: System-Wide Installation

```bash
# Install dependencies system-wide
pip install -r requirements.txt

# Initialize database
python init_db.py

# Run app
python app.py
```

### Option 3: Install as Python Package

```bash
# Install the package
pip install .

# Initialize database
python init_db.py

# Run app
python app.py
```

---

## Production Deployment

### Using Waitress (Windows/Linux)

```bash
# Install Waitress
pip install waitress

# Run the app
waitress-serve --host=0.0.0.0 --port=8080 app:app
```

### Using Gunicorn (Linux/Mac)

```bash
# Install Gunicorn
pip install gunicorn

# Run the app
gunicorn -w 4 -b 0.0.0.0:8080 app:app
```

### Running as a Service (Linux)

Create a systemd service file:

```bash
sudo nano /etc/systemd/system/dh-webapp.service
```

Add the following content:
```ini
[Unit]
Description=DH Member Database Web Application
After=network.target

[Service]
Type=simple
User=your-username
WorkingDirectory=/path/to/DH_DB_Webapp
Environment="PATH=/path/to/venv/bin"
ExecStart=/path/to/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl enable dh-webapp
sudo systemctl start dh-webapp
sudo systemctl status dh-webapp
```

---

## Cloud Deployment

### PythonAnywhere

1. Sign up at pythonanywhere.com
2. Open a Bash console
3. Clone your repository
4. Install dependencies: `pip3 install --user -r requirements.txt`
5. Initialize database: `python3 init_db.py`
6. Configure WSGI file in Web tab
7. Reload web app

### Render

1. Create account at render.com
2. Create new Web Service
3. Connect GitHub repository
4. Set build command: `pip install -r requirements.txt`
5. Set start command: `gunicorn app:app`
6. Deploy

### Railway

1. Create account at railway.app
2. New Project → Deploy from GitHub
3. Select repository
4. Railway auto-detects Python and deploys
5. Add initialization command in settings

---

## Troubleshooting

### "No module named 'flask'"
```bash
pip install Flask
```

### "No such table: members"
```bash
python init_db.py
```

### Port already in use
Change the port in `app.py`:
```python
app.run(debug=True, port=5001)  # Use different port
```

### Permission denied (Linux)
```bash
# Make sure you own the directory
sudo chown -R $USER:$USER .

# Or run with appropriate permissions
sudo python app.py
```

### Database locked
- Close any other connections to members.db
- Check file permissions: `chmod 644 members.db`
- Restart the application

### Can't access from other devices

Edit `app.py` and change:
```python
app.run(debug=True, host='0.0.0.0', port=5000)
```

Then access via: `http://YOUR_COMPUTER_IP:5000`

---

## Updating the Application

### Pull Latest Changes

```bash
# Stop the application (Ctrl+C)

# Pull updates
git pull origin main

# Update dependencies
pip install -r requirements.txt

# Database may auto-update, or run migrations if provided

# Restart application
python app.py
```

### Manual Update

1. Download latest version
2. Replace all files EXCEPT `members.db` (keep your data!)
3. Run `pip install -r requirements.txt`
4. Restart application

---

## Database Backup

### Manual Backup

```bash
# Copy the database file
cp members.db members_backup_$(date +%Y%m%d).db
```

### Automated Backup (Linux)

Create a cron job:
```bash
crontab -e
```

Add this line (daily backup at 2 AM):
```
0 2 * * * cp /path/to/DH_DB_Webapp/members.db /path/to/backups/members_$(date +\%Y\%m\%d).db
```

---

## Next Steps

1. ✅ Access the application at `http://127.0.0.1:5000`
2. ✅ Add your first member
3. ✅ Explore the reports section
4. ✅ Configure production settings if deploying remotely
5. ✅ Set up regular database backups

For support, refer to README.md or contact the administrator.
