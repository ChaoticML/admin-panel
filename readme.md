A modern Flask-based admin panel for managing repair shop tickets, users, and reports.

## Features
- User authentication (Admin, Technician, Viewer roles)
- Ticket management (create, edit, assign, attach files)
- User management (add, edit, delete users)
- Dashboard and reporting (under construction)
- Responsive, modern UI (Bootstrap 5)
- Email notifications (via Flask-Mail)

## Requirements
- **Python version:** 3.9 or newer (recommended: 3.10+)
- **Database:** SQLite (default, file-based)
- **Frontend:** Bootstrap 5, Bootstrap Icons (via CDN)

## Python Dependencies
Install with pip:
```
pip install Flask Flask-Mail Werkzeug
```
Optional (for .env support):
```
pip install python-dotenv
```

## Quickstart
1. **Clone the repository**
2. **Install dependencies** (see above)
3. **Set environment variables** (see below)
4. **Run the app:**
   ```
   python app.py
   ```
5. **Access the app:**  
   Open [http://localhost:5000](http://localhost:5000) in your browser.

## Environment Variables
Set these in your environment or in a `.env` file:
- `SECRET_KEY` (required, for Flask sessions)
- `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER` (for email)
- `ADMIN_EMAIL` (for admin notifications)
- `DATABASE` (optional, path to SQLite DB)

Example `.env`:
```
SECRET_KEY=your_secret_key_here
MAIL_SERVER=smtp.example.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your@email.com
MAIL_PASSWORD=yourpassword
MAIL_DEFAULT_SENDER=Repair Shop <noreply@yourrepairshop.com>
ADMIN_EMAIL=admin@yourrepairshop.com
```

## File Uploads
- Max file size: 5MB per file (configurable)
- Allowed types: png, jpg, jpeg, gif, pdf, doc, docx, txt

## Development Notes
- All templates are in the templates folder.
- Static files (if any) should be placed in a `static/` folder (not included by default).
- Logging is written to app.log.
