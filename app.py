from flask import Flask, render_template, request, redirect, flash, url_for, session, send_from_directory
from flask_mail import Mail, Message
import sqlite3
from datetime import datetime
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename # Added
import logging

app = Flask(__name__)

# --- Configuration ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.example.com') # Replace with your actual mail server
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587)) # Common port for TLS
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@example.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-email-password')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', ('Repair Shop', 'noreply@yourrepairshop.com')) # Tuple for name and email
app.config['ADMIN_EMAIL'] = os.environ.get('ADMIN_EMAIL', 'admin@yourrepairshop.com')
app.config['DATABASE'] = os.environ.get('DATABASE', os.path.join(os.path.dirname(__file__), 'database.db'))
app.secret_key = os.environ.get('SECRET_KEY', 'your_very_secure_random_secret_key_please_change_me') # CHANGE THIS!
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB per file
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt'}

# --- Constants ---
ROLE_ADMIN = 'admin'
ROLE_TECHNICIAN = 'technician'
ROLE_VIEWER = 'viewer'

STATUS_OPEN = 'Open'
STATUS_IN_PROGRESS = 'In Progress'
STATUS_COMPLETED = 'Completed'
STATUS_ON_HOLD = 'On Hold'

TICKET_CATEGORIES = ['Hardware Issue', 'Software Issue', 'Network Issue', 'Maintenance', 'Consultation', 'Other']
TICKET_PRIORITIES = ['Low', 'Normal', 'High', 'Urgent']


# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler() # Also log to console
    ]
)
logger = logging.getLogger(__name__)

mail = Mail(app)

# --- Helper Functions ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'], detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute(f'''CREATE TABLE IF NOT EXISTS tickets
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT '{STATUS_OPEN}',
                category TEXT,
                created_at DATETIME NOT NULL,
                updated_at DATETIME,
                completed_at DATETIME,
                customer_name TEXT NOT NULL,
                customer_email TEXT,
                customer_phone TEXT,
                device_type TEXT,
                serial_number TEXT,
                priority TEXT DEFAULT '{TICKET_PRIORITIES[1]}',
                assigned_technician_id INTEGER,
                created_by_user_id INTEGER,
                notes TEXT,
                attachments TEXT,
                FOREIGN KEY (assigned_technician_id) REFERENCES users(id),
                FOREIGN KEY (created_by_user_id) REFERENCES users(id)
                )''')
            
            c.execute(f'''CREATE TABLE IF NOT EXISTS users
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE,
                role TEXT NOT NULL DEFAULT '{ROLE_TECHNICIAN}',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            
            admin_username = 'admin'
            admin_email_config = app.config['ADMIN_EMAIL']
            c.execute("SELECT * FROM users WHERE username = ?", (admin_username,))
            if not c.fetchone():
                if not admin_email_config: # Check if the configured ADMIN_EMAIL is empty
                    logger.warning(f"ADMIN_EMAIL environment variable is not set. Default admin user '{admin_username}' will be created without an email address.")
                
                hashed_password = generate_password_hash(os.environ.get('ADMIN_DEFAULT_PASSWORD', 'admin123'))
                try:
                    c.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                             (admin_username, hashed_password, admin_email_config if admin_email_config else None, ROLE_ADMIN))
                    logger.info(f"Default admin user '{admin_username}' created.")
                except sqlite3.IntegrityError as ie:
                     logger.warning(f"Could not create default admin '{admin_username}', possibly due to existing email '{admin_email_config}': {ie}")

            c.execute("CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets (status)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_tickets_priority ON tickets (priority)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_tickets_assigned_technician_id ON tickets (assigned_technician_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_tickets_created_at ON tickets (created_at)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)")

            conn.commit()
            logger.info("Database initialized/checked successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}", exc_info=True)
        raise

# --- Context Processors ---
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@app.context_processor
def utility_processor():
    return dict(
        ROLE_ADMIN=ROLE_ADMIN,
        ROLE_TECHNICIAN=ROLE_TECHNICIAN,
        ROLE_VIEWER=ROLE_VIEWER,
        TICKET_CATEGORIES=TICKET_CATEGORIES,
        TICKET_PRIORITIES=TICKET_PRIORITIES,
        STATUS_OPEN=STATUS_OPEN,
        STATUS_IN_PROGRESS=STATUS_IN_PROGRESS,
        STATUS_COMPLETED=STATUS_COMPLETED,
        STATUS_ON_HOLD=STATUS_ON_HOLD,
        ADMIN_EMAIL=app.config['ADMIN_EMAIL'] # Make ADMIN_EMAIL available to templates if needed
    )

# --- Authentication Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get('role') != ROLE_ADMIN:
            flash('Admin access required for this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Auth Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT * FROM users WHERE username = ?", (username,))
                user = c.fetchone()
                if user and check_password_hash(user['password'], password):
                    session['logged_in'] = True
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    flash(f'Welcome back, {username}!', 'success')
                    next_url = request.args.get('next')
                    return redirect(next_url or url_for('index'))
                else:
                    error = 'Invalid username or password. Please try again.'
        except Exception as e:
            logger.error(f"Login error: {e}", exc_info=True)
            error = 'A system error occurred during login. Please try again later.'
    return render_template('login.html', error=error, title="Login")

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')
    return redirect(url_for('login'))

# --- User Management (Admin Only) ---
@app.route('/users')
@admin_required
def list_users():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT id, username, email, role, created_at FROM users ORDER BY username')
        users = c.fetchall()
    return render_template('users.html', users=users, title="User Management")

@app.route('/users/add', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
        elif not username or not email or not password or not role: # Basic check
            flash('All fields are required.', 'danger')
        else:
            hashed_password = generate_password_hash(password)
            try:
                with get_db_connection() as conn:
                    c = conn.cursor()
                    c.execute('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                              (username, email, hashed_password, role))
                    conn.commit()
                flash(f'User {username} added successfully.', 'success')
                return redirect(url_for('list_users'))
            except sqlite3.IntegrityError:
                flash(f'Username or email already exists.', 'danger')
            except Exception as e:
                logger.error(f"Error adding user: {e}", exc_info=True)
                flash(f'Error adding user: {str(e)}', 'danger')
    return render_template('add_user.html', title="Add New User", form_data=request.form if request.method == 'POST' else {})


@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user_data_for_template = {}
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT id, username, email, role FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
    
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('list_users'))

    user_data_for_template = dict(user)

    if request.method == 'POST':
        new_username = request.form['username']
        new_email = request.form['email']
        new_role = request.form['role']
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        user_data_for_template.update(request.form.to_dict()) # Keep submitted values for re-render on error

        if not new_username or not new_email or not new_role:
            flash('Username, email, and role are required.', 'danger')
            return render_template('edit_user.html', user=user_data_for_template, title=f"Edit User: {user_data_for_template['username']}")

        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                if new_username != user['username']:
                    c.execute("SELECT id FROM users WHERE username = ? AND id != ?", (new_username, user_id))
                    if c.fetchone():
                        flash('That username is already taken by another user.', 'danger')
                        return render_template('edit_user.html', user=user_data_for_template, title=f"Edit User: {user_data_for_template['username']}")
                if new_email != user['email']: # Ensure email is not None before comparing
                    c.execute("SELECT id FROM users WHERE email = ? AND id != ?", (new_email, user_id))
                    if c.fetchone():
                        flash('That email address is already used by another user.', 'danger')
                        return render_template('edit_user.html', user=user_data_for_template, title=f"Edit User: {user_data_for_template['username']}")

                if new_password:
                    if new_password != confirm_password:
                        flash('New passwords do not match.', 'danger')
                        return render_template('edit_user.html', user=user_data_for_template, title=f"Edit User: {user_data_for_template['username']}")
                    hashed_password = generate_password_hash(new_password)
                    c.execute('UPDATE users SET username=?, email=?, password=?, role=? WHERE id=?',
                              (new_username, new_email, hashed_password, new_role, user_id))
                else:
                    c.execute('UPDATE users SET username=?, email=?, role=? WHERE id=?',
                              (new_username, new_email, new_role, user_id))
                conn.commit()
            flash(f"User '{new_username}' updated successfully.", 'success')
            return redirect(url_for('list_users'))
        except sqlite3.IntegrityError:
            flash('Update failed. Username or email might already exist for another user.', 'danger')
        except Exception as e:
            logger.error(f"Error updating user {user_id}: {e}", exc_info=True)
            flash(f'Error updating user: {str(e)}', 'danger')
        # On error, re-render with user_data_for_template which has submitted values
        return render_template('edit_user.html', user=user_data_for_template, title=f"Edit User: {user_data_for_template['username']}")

    return render_template('edit_user.html', user=user_data_for_template, title=f"Edit User: {user_data_for_template['username']}")


@app.route('/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash("You cannot delete your own account.", 'danger')
        return redirect(url_for('list_users'))
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
            user = c.fetchone()
            if not user:
                flash("User not found.", "danger")
                return redirect(url_for('list_users'))
            
            c.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
        flash(f"User '{user['username']}' deleted successfully.", 'success')
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}", exc_info=True)
        flash(f'Error deleting user: {str(e)}', 'danger')
    return redirect(url_for('list_users'))

# --- Ticket Routes ---
@app.route('/')
@login_required
def index():
    status_filter = request.args.get('status', 'all')
    priority_filter = request.args.get('priority', 'all')
    search_term = request.args.get('search', '')

    allowed_sort_columns = ['id', 'description', 'status', 'created_at', 'customer_name', 'priority', 'category', 'device_type']
    sort_by = request.args.get('sort', 'id')
    if sort_by not in allowed_sort_columns:
        sort_by = 'id'
    
    sort_order_input = request.args.get('order', 'desc').lower()
    sql_sort_order = 'DESC' if sort_order_input == 'desc' else 'ASC'
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            base_query = """
                SELECT t.*, u_assigned.username as assigned_technician_username, u_created.username as created_by_username
                FROM tickets t
                LEFT JOIN users u_assigned ON t.assigned_technician_id = u_assigned.id
                LEFT JOIN users u_created ON t.created_by_user_id = u_created.id
            """
            conditions = []
            params = []

            if status_filter != 'all':
                conditions.append("t.status = ?")
                params.append(status_filter)
            if priority_filter != 'all':
                conditions.append("t.priority = ?")
                params.append(priority_filter)
            if search_term:
                conditions.append("(t.description LIKE ? OR t.customer_name LIKE ? OR t.id LIKE ? OR t.device_type LIKE ? OR t.serial_number LIKE ?)")
                search_like = f"%{search_term}%"
                params.extend([search_like, search_like, search_like, search_like, search_like])

            if conditions:
                query = base_query + " WHERE " + " AND ".join(conditions)
            else:
                query = base_query
            
            query += f' ORDER BY t.{sort_by} {sql_sort_order}'
            
            c.execute(query, params)
            tickets = c.fetchall()
            
            c.execute("SELECT status, COUNT(*) as count FROM tickets GROUP BY status")
            status_counts = {row['status']: row['count'] for row in c.fetchall()}
            
            c.execute("SELECT priority, COUNT(*) as count FROM tickets GROUP BY priority")
            priority_counts = {row['priority']: row['count'] for row in c.fetchall()}

            c.execute("SELECT id, username FROM users WHERE role IN (?, ?)", (ROLE_ADMIN, ROLE_TECHNICIAN))
            technicians = c.fetchall()

            return render_template('index.html', 
                                  tickets=tickets, 
                                  status_filter=status_filter,
                                  priority_filter=priority_filter,
                                  search_term=search_term,
                                  sort_by=sort_by,
                                  sort_order=sort_order_input,
                                  status_counts=status_counts,
                                  priority_counts=priority_counts,
                                  technicians=technicians,
                                  title="Ticket Dashboard")
    except Exception as e:
        logger.error(f"Index page error: {e}", exc_info=True)
        flash('Error retrieving tickets. Please check logs.', 'danger')
        return render_template('index.html', tickets=[], error=str(e), title="Ticket Dashboard")

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_ticket():
    technicians_list = []
    with get_db_connection() as conn_tech: # Fetch technicians for all cases
        c_tech = conn_tech.cursor()
        c_tech.execute("SELECT id, username FROM users WHERE role IN (?, ?)", (ROLE_ADMIN, ROLE_TECHNICIAN))
        technicians_list = c_tech.fetchall()

    if request.method == 'POST':
        try:
            description = request.form['description']
            category = request.form.get('category')
            priority = request.form.get('priority')
            customer_name = request.form['customer_name']
            customer_email = request.form.get('customer_email')
            customer_phone = request.form.get('customer_phone')
            device_type = request.form.get('device_type')
            serial_number = request.form.get('serial_number')
            assigned_technician_id = request.form.get('assigned_technician_id')
            notes = request.form.get('notes', '')
            
            attachments = request.files.getlist('attachments')
            saved_files = []

            if not description or not customer_name or not category or not priority:
                flash('Description, Customer Name, Category, and Priority are required fields.', 'danger')
                return render_template('create_ticket.html', form_data=request.form, technicians=technicians_list, title="Create New Ticket"), 400

            if attachments:
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                for file in attachments:
                    if file and file.filename and allowed_file(file.filename):
                        original_filename = secure_filename(file.filename)
                        filename = f"{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{original_filename}"
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(filepath)
                        saved_files.append(filename)
                    elif file and file.filename and not allowed_file(file.filename):
                        flash(f"File type not allowed for {secure_filename(file.filename)}", "warning")

            attachments_str = ','.join(saved_files) if saved_files else None

            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute('''
                    INSERT INTO tickets 
                    (description, status, category, created_at, updated_at, customer_name, customer_email, customer_phone,
                     device_type, serial_number, priority, assigned_technician_id, created_by_user_id, notes, attachments) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (description, STATUS_OPEN, category, datetime.now(), datetime.now(), customer_name, customer_email, customer_phone,
                      device_type, serial_number, priority, assigned_technician_id if assigned_technician_id else None, 
                      session['user_id'], notes, attachments_str))
                conn.commit()
                ticket_id = c.lastrowid
            flash(f'Ticket #{ticket_id} created successfully!', 'success')
            return redirect(url_for('view_ticket', ticket_id=ticket_id))
        except Exception as e:
            logger.error(f"Create ticket error: {e}", exc_info=True)
            flash(f'Error creating ticket: {str(e)}', 'danger')
            return render_template('create_ticket.html', form_data=request.form, technicians=technicians_list, title="Create New Ticket")

    return render_template('create_ticket.html', form_data={}, technicians=technicians_list, title="Create New Ticket")


@app.route('/ticket/<int:ticket_id>/update_status', methods=['POST'])
@login_required
def update_ticket_status(ticket_id):
    new_status = request.form.get('status')
    if not new_status:
        flash("No status provided for update.", "warning")
        return redirect(request.referrer or url_for('index'))
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status, customer_email, customer_name, device_type, description, serial_number FROM tickets WHERE id = ?", (ticket_id,))
            ticket = c.fetchone()

            if not ticket:
                flash(f"Ticket #{ticket_id} not found.", "danger")
                return redirect(url_for('index'))

            completed_at_val = datetime.now() if new_status == STATUS_COMPLETED and ticket['status'] != STATUS_COMPLETED else None
            
            c.execute('''UPDATE tickets SET status = ?, updated_at = ?, completed_at = COALESCE(?, completed_at)
                         WHERE id = ?''', 
                      (new_status, datetime.now(), completed_at_val, ticket_id))
            conn.commit()
            flash(f"Ticket #{ticket_id} status updated to {new_status}.", "success")

            if new_status == STATUS_COMPLETED and ticket['status'] != STATUS_COMPLETED and ticket['customer_email']:
                try:
                    # Re-fetch ticket to get all details for email template if needed, or pass existing 'ticket'
                    c.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)) # Get full ticket for email
                    email_ticket_data = c.fetchone()
                    msg = Message(
                        f"Repair Ticket #{ticket_id} Completed",
                        recipients=[email_ticket_data['customer_email']],
                        cc=[app.config['ADMIN_EMAIL']] if app.config['ADMIN_EMAIL'] else None
                    )
                    msg.html = render_template('email/ticket_completed_email.html', ticket=email_ticket_data, ticket_id=ticket_id)
                    mail.send(msg)
                    logger.info(f"Completion email sent for ticket #{ticket_id}")
                except Exception as e:
                    logger.error(f"Email sending error for ticket #{ticket_id}: {e}", exc_info=True)
                    flash('Ticket status updated, but email notification failed. Please check mail server configuration.', 'warning')
        
    except Exception as e:
        logger.error(f"Update ticket status error for ticket {ticket_id}: {e}", exc_info=True)
        flash(f'Error updating ticket status: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('view_ticket', ticket_id=ticket_id))


@app.route('/ticket/<int:ticket_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_ticket(ticket_id):
    ticket_data_for_template = {}
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT t.*, u_assigned.username as assigned_technician_username
            FROM tickets t
            LEFT JOIN users u_assigned ON t.assigned_technician_id = u_assigned.id
            WHERE t.id = ?
        """, (ticket_id,))
        ticket = c.fetchone()
        
        c.execute("SELECT id, username FROM users WHERE role IN (?, ?)", (ROLE_ADMIN, ROLE_TECHNICIAN))
        technicians = c.fetchall()

    if not ticket:
        flash(f'Ticket #{ticket_id} not found.', 'danger')
        return redirect(url_for('index'))

    ticket_data_for_template = dict(ticket) # Initialize with database data

    if request.method == 'POST':
        ticket_data_for_template.update(request.form.to_dict()) # Update with form data for repopulation on error

        description = request.form['description']
        category = request.form.get('category')
        priority = request.form.get('priority')
        status = request.form.get('status')
        customer_name = request.form['customer_name']
        # ... (get other form fields)

        if not description or not customer_name or not category or not priority or not status:
            flash('Description, Customer Name, Category, Priority, and Status are required fields.', 'danger')
            return render_template('edit_ticket.html', ticket=ticket_data_for_template, technicians=technicians, title=f"Edit Ticket #{ticket_id}"), 400
        
        try:
            completed_at_val = ticket['completed_at'] # Original value
            if status == STATUS_COMPLETED and ticket['status'] != STATUS_COMPLETED:
                completed_at_val = datetime.now()
            elif status != STATUS_COMPLETED and ticket['status'] == STATUS_COMPLETED:
                completed_at_val = None

            with get_db_connection() as conn_update:
                cu = conn_update.cursor()
                cu.execute('''
                    UPDATE tickets SET
                    description=?, category=?, priority=?, status=?, customer_name=?, customer_email=?, customer_phone=?,
                    device_type=?, serial_number=?, assigned_technician_id=?, notes=?, updated_at=?, completed_at=?
                    WHERE id=?
                ''', (request.form['description'], request.form.get('category'), request.form.get('priority'), 
                      request.form.get('status'), request.form['customer_name'], request.form.get('customer_email'),
                      request.form.get('customer_phone'), request.form.get('device_type'), request.form.get('serial_number'),
                      request.form.get('assigned_technician_id') if request.form.get('assigned_technician_id') else None, 
                      request.form.get('notes', ''), datetime.now(), completed_at_val, ticket_id))
                conn_update.commit()
            flash(f'Ticket #{ticket_id} updated successfully!', 'success')
            return redirect(url_for('view_ticket', ticket_id=ticket_id))
        except Exception as e:
            logger.error(f"Edit ticket error for ticket {ticket_id}: {e}", exc_info=True)
            flash(f'Error updating ticket: {str(e)}', 'danger')
            # ticket_data_for_template already has the submitted values
            return render_template('edit_ticket.html', ticket=ticket_data_for_template, technicians=technicians, title=f"Edit Ticket #{ticket_id}")

    return render_template('edit_ticket.html', ticket=ticket_data_for_template, technicians=technicians, title=f"Edit Ticket #{ticket_id}")


@app.route('/ticket/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT t.*, u_assigned.username as assigned_technician_username, u_created.username as created_by_username
                FROM tickets t
                LEFT JOIN users u_assigned ON t.assigned_technician_id = u_assigned.id
                LEFT JOIN users u_created ON t.created_by_user_id = u_created.id
                WHERE t.id = ?
            """, (ticket_id,))
            ticket = c.fetchone()
            
            if not ticket:
                flash(f'Ticket #{ticket_id} not found.', 'danger')
                return redirect(url_for('index'))
            
            attachments = ticket['attachments'].split(',') if ticket['attachments'] else []
            
            return render_template('view_ticket.html', ticket=ticket, attachments=attachments, title=f"View Ticket #{ticket['id']}")
    except Exception as e:
        logger.error(f"View ticket error for ticket {ticket_id}: {e}", exc_info=True)
        flash(f'Error retrieving ticket details: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/ticket/<int:ticket_id>/add_note', methods=['POST'])
@login_required
def add_ticket_note(ticket_id):
    note_content = request.form.get('note_content')
    if not note_content:
        flash("Note content cannot be empty.", "warning")
        return redirect(url_for('view_ticket', ticket_id=ticket_id))

    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT notes FROM tickets WHERE id = ?", (ticket_id,))
            ticket = c.fetchone()
            if not ticket:
                flash(f"Ticket #{ticket_id} not found.", "danger")
                return redirect(url_for('index'))

            current_notes = ticket['notes'] if ticket['notes'] else ""
            # Ensure new notes are always appended with the separator for consistent parsing
            separator = "\n---\n" if current_notes.strip() else "" # Add separator only if there's existing content
            new_note_entry = f"{separator}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by {session['username']}:\n{note_content}"
            updated_notes = current_notes + new_note_entry
            
            c.execute("UPDATE tickets SET notes = ?, updated_at = ? WHERE id = ?", (updated_notes, datetime.now(), ticket_id))
            conn.commit()
            flash("Note added successfully.", "success")
    except Exception as e:
        logger.error(f"Error adding note to ticket {ticket_id}: {e}", exc_info=True)
        flash(f"Error adding note: {str(e)}", "danger")
    return redirect(url_for('view_ticket', ticket_id=ticket_id))


@app.route('/delete/<int:ticket_id>', methods=['POST'])
@login_required
def delete_ticket(ticket_id):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT attachments FROM tickets WHERE id = ?", (ticket_id,))
            ticket = c.fetchone()
            if ticket and ticket['attachments']:
                for filename in ticket['attachments'].split(','):
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        logger.info(f"Deleted attachment {filename} for ticket {ticket_id}")
                    except OSError as oe:
                        logger.error(f"Error deleting attachment {filename}: {oe}")
            
            c.execute('DELETE FROM tickets WHERE id = ?', (ticket_id,))
            conn.commit()
        flash(f'Ticket #{ticket_id} and its attachments deleted successfully.', 'success')
    except Exception as e:
        logger.error(f"Delete ticket error for ticket {ticket_id}: {e}", exc_info=True)
        flash(f'Error deleting ticket: {str(e)}', 'danger')
    return redirect(url_for('index'))

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    if '..' in filename or filename.startswith('/'):
        flash("Invalid filename.", "danger")
        return redirect(url_for('index')) 
    
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        logger.warning(f"Requested attachment not found: {filename}")
        flash("Attachment not found.", "warning")
        return redirect(request.referrer or url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status, COUNT(*) as count FROM tickets GROUP BY status")
            status_counts = {row['status']: row['count'] for row in c.fetchall()}
            
            c.execute("SELECT priority, COUNT(*) as count FROM tickets GROUP BY priority")
            priority_counts = {row['priority']: row['count'] for row in c.fetchall()}
            
            c.execute("SELECT category, COUNT(*) as count FROM tickets GROUP BY category ORDER BY count DESC")
            category_counts = {row['category'] if row['category'] else 'N/A': row['count'] for row in c.fetchall()}


            c.execute("""
                SELECT t.id, t.description, t.status, t.priority, t.created_at, u.username as assigned_technician_username
                FROM tickets t
                LEFT JOIN users u ON t.assigned_technician_id = u.id
                ORDER BY t.created_at DESC LIMIT 10
            """)
            recent_tickets = c.fetchall()

            c.execute("""
                SELECT u.username, COUNT(t.id) as ticket_count
                FROM users u
                LEFT JOIN tickets t ON u.id = t.assigned_technician_id AND t.status != ?
                WHERE u.role IN (?, ?)
                GROUP BY u.id, u.username
                ORDER BY ticket_count DESC
            """, (STATUS_COMPLETED, ROLE_ADMIN, ROLE_TECHNICIAN))
            technician_load = c.fetchall()

            return render_template('dashboard.html', 
                                  status_counts=status_counts,
                                  priority_counts=priority_counts,
                                  category_counts=category_counts,
                                  recent_tickets=recent_tickets,
                                  technician_load=technician_load,
                                  title="System Dashboard")
    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        flash(f'Error loading dashboard: {str(e)}', 'danger')
        return redirect(url_for('index'))

# --- Placeholder Routes ---
@app.route('/reports')
@login_required
def reports():
    flash("The reports page is under construction.", "info")
    return render_template('reports.html', title="Reports")

@app.route('/settings')
@admin_required
def settings():
    flash("The settings page is under construction.", "info")
    return render_template('settings.html', title="Settings")


# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    logger.warning(f"404 Not Found: {request.url} (Referrer: {request.referrer}) - {e}")
    return render_template('404.html', title="Page Not Found"), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"500 Internal Server Error: {request.url} - {e}", exc_info=True)
    return render_template('500.html', title="Server Error"), 500

@app.errorhandler(403)
def forbidden_error(e):
    logger.warning(f"403 Forbidden: {request.url} - {e}")
    return render_template('403.html', title="Access Forbidden"), 403

@app.errorhandler(401)
def unauthorized_error(e):
    logger.warning(f"401 Unauthorized: {request.url} - {e}")
    flash("You need to be logged in to access this page.", "warning")
    return redirect(url_for('login', next=request.url))


if __name__ == '__main__':
    # Initialize DB (creates tables/indexes if they don't exist)
    init_db() 

    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        logger.info(f"Uploads folder created at {app.config['UPLOAD_FOLDER']}")

    app.run(host='127.0.0.1', port=5000, debug=True)