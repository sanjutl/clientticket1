from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta

def get_ist_time():
    return datetime.utcnow() + timedelta(hours=5, minutes=30)

app = Flask(__name__)
app.secret_key = 'your_secret_key'

UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

DATABASE = 'tickets.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name TEXT,
            country TEXT,
            state TEXT,
            location TEXT,
            issue_type TEXT,
            subject TEXT,
            description TEXT,
            attachment TEXT,
            priority TEXT,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS developers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS developer_dashboard (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name TEXT,
            country TEXT,
            state TEXT,
            location TEXT,
            issue_type TEXT,
            subject TEXT,
            description TEXT,
            attachment TEXT,
            priority TEXT,
            email TEXT,
            status TEXT DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Ensure default admin exists
    admin = conn.execute('SELECT * FROM admins WHERE username = ?', ('admin',)).fetchone()
    if not admin:
        hashed_admin_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
        conn.execute('INSERT INTO admins (username, password_hash) VALUES (?, ?)', ('admin', hashed_admin_pw))

    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit-ticket')
def submit_ticket():
    return render_template('user_ticketpage.html')

@app.route('/submit', methods=['POST'])
def submit():
    data = {
        'app_name': request.form.get('appName'),
        'country': request.form.get('country'),
        'state': request.form.get('state'),
        'location': request.form.get('location'),
        'issue_type': request.form.get('issueType'),
        'subject': request.form.get('subject'),
        'description': request.form.get('description'),
        'priority': request.form.get('priority'),
        'email': request.form.get('email'),
    }

    file = request.files.get('attachment')
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        data['attachment'] = filename
    else:
        data['attachment'] = None

    created_at = get_ist_time()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO tickets (app_name, country, state, location, issue_type, subject, description, attachment, priority, email, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['app_name'], data['country'], data['state'], data['location'],
        data['issue_type'], data['subject'], data['description'],
        data['attachment'], data['priority'], data['email'], created_at
    ))

    cursor.execute('''
        INSERT INTO developer_dashboard (app_name, country, state, location, issue_type, subject, description, attachment, priority, email, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['app_name'], data['country'], data['state'], data['location'],
        data['issue_type'], data['subject'], data['description'],
        data['attachment'], data['priority'], data['email'], 'Pending', created_at
    ))

    conn.commit()
    conn.close()

    flash("Ticket submitted successfully!", "success")
    return redirect('/')

@app.route('/developer_login', methods=['GET', 'POST'])
def developer_login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password']

        conn = get_db_connection()
        developer = conn.execute('SELECT * FROM developers WHERE email = ?', (email,)).fetchone()
        conn.close()

        if developer and check_password_hash(developer['password_hash'], password):
            session['developer_id'] = developer['id']
            session['developer_email'] = developer['email']
            flash('Login successful!', 'success')
            return redirect(url_for('developer_dashboard'))
        else:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('developer_login'))

    return render_template('developer_login.html')

@app.route('/developer_dashboard')
def developer_dashboard():
    conn = get_db_connection()
    bugs = conn.execute("SELECT * FROM developer_dashboard WHERE status != 'resolved' ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template('developer_dashboard.html', bugs=bugs)

@app.route('/update_status/<int:ticket_id>', methods=['POST'])
def update_status(ticket_id):
    new_status = request.form.get('status')
    conn = get_db_connection()
    conn.execute('UPDATE developer_dashboard SET status = ? WHERE id = ?', (new_status, ticket_id))
    conn.commit()
    conn.close()
    flash('Status updated successfully.', 'success')
    return redirect(url_for('developer_dashboard'))

@app.route('/developer_update', methods=['POST'])
def developer_update():
    bug_id = request.form.get('bug_id')
    issue_type = request.form.get('issue_type')
    priority = request.form.get('priority')
    subject = request.form.get('subject')
    location = request.form.get('location')
    state = request.form.get('state')
    country = request.form.get('country')
    description = request.form.get('description')
    created_at = request.form.get('time_reported')
    status = request.form.get('status')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE developer_dashboard
        SET issue_type = ?, priority = ?, subject = ?, location = ?, state = ?, country = ?,
            description = ?, created_at = ?, status = ?
        WHERE id = ?
    ''', (issue_type, priority, subject, location, state, country, description, created_at, status, bug_id))
    conn.commit()
    conn.close()

    flash('Bug status updated successfully!', 'info')
    return redirect(url_for('developer_dashboard'))

@app.route('/developer_signup', methods=['GET', 'POST'])
def developer_signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO developers (email, password_hash) VALUES (?, ?)", (email, password_hash))
        conn.commit()
        conn.close()

        flash('Signup successful. Please log in.', 'success')
        return redirect(url_for('developer_login'))

    return render_template('developer_signup.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        conn = get_db_connection()
        admin = conn.execute('SELECT * FROM admins WHERE username = ?', (username,)).fetchone()
        conn.close()

        if admin and check_password_hash(admin['password_hash'], password):
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    conn = get_db_connection()
    updates = conn.execute('SELECT * FROM developer_dashboard').fetchall()
    conn.close()
    return render_template('admin_dashboard.html', updates=updates)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
