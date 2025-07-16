import os
import sqlite3
import datetime
import csv
import io
from flask import (
    Flask, render_template, redirect, url_for, request,
    session, flash, send_file, g, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from fpdf import FPDF
from functools import wraps
from database import init_db, get_db

app = Flask(__name__)
app.secret_key = "supersecret"
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
init_db()

# ----------- Context Processor ----------
@app.context_processor
def inject_settings():
    db = get_db()
    try:
        settings_data = db.execute("SELECT key, value FROM settings").fetchall()
        return {
            'settings': {row['key']: row['value'] for row in settings_data}
        }
    except Exception:
        return {'settings': {}}

# ----------- Decorators ----------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            flash("Login required")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_only(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session or session['user']['role'] != 'admin':
            flash("Admin access only")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

# ----------- Routes --------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    db = get_db()
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not user:
            flash("User does not exist.")
        elif not check_password_hash(user['password'], password):
            flash("Incorrect password.")
        else:
            session['user'] = dict(user)
            flash("Login successful")
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    db = get_db()
    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        username = request.form['username'].lower()
        if username == 'admin':
            flash("You cannot register as admin.")
            return redirect(url_for('register'))
        password = generate_password_hash(request.form['password'])
        try:
            db.execute("INSERT INTO users (name, phone, username, password, role) VALUES (?, ?, ?, ?, ?)",
                       (name, phone, username, password, 'user'))
            db.commit()
            user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            session['user'] = dict(user)
            flash("Registration successful.")
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError as e:
            flash("Registration failed: " + str(e))
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    db = get_db()
    user = session['user']
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    search = request.form.get('search')

    params = []
    if user['role'] == 'admin':
        query = "SELECT * FROM transactions WHERE 1=1"
        if start_date and end_date:
            query += " AND date BETWEEN ? AND ?"
            params += [start_date, end_date]
        if search:
            query += " AND (description LIKE ? OR amount LIKE ?)"
            params += [f"%{search}%", f"%{search}%"]
        query += " ORDER BY date DESC"
        transactions = db.execute(query, params).fetchall()
        users = db.execute("SELECT * FROM users WHERE username != 'admin'").fetchall()
        labels = ['income', 'expense', 'advance']
        chart_data = [db.execute("SELECT SUM(amount) FROM transactions WHERE type=?", (label,)).fetchone()[0] or 0 for label in labels]
        return render_template('admin_panel.html', users=users, transactions=transactions, labels=labels, data=chart_data, zip=zip)
    else:
        query = "SELECT * FROM transactions WHERE user_id=?"
        params = [user['id']]
        if start_date and end_date:
            query += " AND date BETWEEN ? AND ?"
            params += [start_date, end_date]
        if search:
            query += " AND (description LIKE ? OR amount LIKE ?)"
            params += [f"%{search}%", f"%{search}%"]
        query += " ORDER BY date DESC"
        transactions = db.execute(query, params).fetchall()
        labels = ['income', 'expense', 'advance']
        data = [db.execute("SELECT SUM(amount) FROM transactions WHERE type=? AND user_id=?", (label, user['id'])).fetchone()[0] or 0 for label in labels]
        return render_template('dashboard.html', transactions=transactions, labels=labels, data=data, zip=zip)

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_only
def admin_settings():
    db = get_db()
    if request.method == 'POST':
        keys = ['site_name', 'currency', 'notification_email', 'report_footer', 'theme_color']
        for key in keys:
            value = request.form.get(key, '')
            db.execute("""
                INSERT INTO settings (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """, (key, value))

        # Handle logo upload
        if 'logo' in request.files:
            logo_file = request.files['logo']
            if logo_file.filename:
                filename = secure_filename(logo_file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                logo_file.save(filepath)
                db.execute("""
                    INSERT INTO settings (key, value)
                    VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """, ('logo_path', filepath.replace("\\", "/")))

        db.commit()
        flash("Settings saved successfully.")
        return redirect(url_for('admin_settings'))

    settings_data = db.execute("SELECT key, value FROM settings").fetchall()
    settings = {row['key']: row['value'] for row in settings_data}
    return render_template('admin_settings.html', settings=settings)

@app.route('/admin/user/<int:user_id>')
@admin_only
def user_activity(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        flash("User not found.")
        return redirect(url_for('dashboard'))
    transactions = db.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY date DESC", (user_id,)).fetchall()
    labels = ['income', 'expense', 'advance']
    data = [db.execute("SELECT SUM(amount) FROM transactions WHERE type=? AND user_id=?", (label, user_id)).fetchone()[0] or 0 for label in labels]
    return render_template('user_activity.html', user=user, transactions=transactions, labels=labels, data=data, zip=zip)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_transaction():
    db = get_db()
    if request.method == 'POST':
        data = request.form
        db.execute("""INSERT INTO transactions (user_id, type, amount, description, date, time) 
                      VALUES (?, ?, ?, ?, ?, ?)""",
                   (session['user']['id'], data['type'], data['amount'], data['description'], 
                    data['date'], data['time']))
        db.commit()
        flash("Transaction added successfully.")
        return redirect(url_for('dashboard'))
    return render_template('add_transaction.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@admin_only
def edit_transaction(id):
    db = get_db()
    if request.method == 'POST':
        data = request.form
        db.execute("""UPDATE transactions 
                      SET type=?, amount=?, description=?, date=?, time=? 
                      WHERE id=?""",
                   (data['type'], data['amount'], data['description'], data['date'], data['time'], id))
        db.commit()
        flash("Transaction updated.")
        return redirect(url_for('dashboard'))
    tx = db.execute("SELECT * FROM transactions WHERE id=?", (id,)).fetchone()
    return render_template('edit_transaction.html', tx=tx)

@app.route('/delete/<int:id>')
@admin_only
def delete_transaction(id):
    db = get_db()
    db.execute("DELETE FROM transactions WHERE id=?", (id,))
    db.commit()
    flash("Transaction deleted.")
    return redirect(url_for('dashboard'))

@app.route('/download')
@admin_only
def download_csv():
    db = get_db()
    transactions = db.execute("SELECT * FROM transactions ORDER BY date DESC").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'User ID', 'Type', 'Amount', 'Description', 'Date', 'Time'])
    for tx in transactions:
        writer.writerow([tx['id'], tx['user_id'], tx['type'], tx['amount'], tx['description'], tx['date'], tx['time']])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='transactions.csv')

@app.route('/download/pdf')
@admin_only
def download_pdf():
    db = get_db()
    transactions = db.execute("SELECT * FROM transactions ORDER BY date DESC").fetchall()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Expense Report", ln=True, align='C')
    pdf.ln(10)
    for tx in transactions:
        row = f"{tx['date']} | {tx['type']} | Ksh {tx['amount']} | {tx['description']}"
        pdf.cell(200, 10, txt=row, ln=True)
    output = io.BytesIO()
    pdf.output(output)
    output.seek(0)
    return send_file(output, as_attachment=True, download_name="report.pdf")

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account_settings():
    db = get_db()
    user = session['user']
    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        password = request.form['password']
        hashed = generate_password_hash(password) if password else user['password']
        db.execute("UPDATE users SET name=?, phone=?, password=? WHERE id=?",
                   (name, phone, hashed, user['id']))
        db.commit()
        flash("Account updated successfully.")
    return render_template('account.html', user=user)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# -------- API (for Mobile) --------
@app.route('/api/login', methods=['POST'])
def api_login():
    db = get_db()
    data = request.get_json()
    username = data['username'].lower()
    password = data['password']
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        return jsonify({"status": "fail", "message": "User not found"}), 404
    if not check_password_hash(user['password'], password):
        return jsonify({"status": "fail", "message": "Incorrect password"}), 401
    return jsonify({"status": "success", "user": dict(user)}), 200

@app.route('/api/register', methods=['POST'])
def api_register():
    db = get_db()
    data = request.get_json()
    username = data['username'].lower()
    if username == 'admin':
        return jsonify({"status": "fail", "message": "Cannot register as admin"}), 403
    name = data['name']
    phone = data['phone']
    password = generate_password_hash(data['password'])
    try:
        db.execute("INSERT INTO users (name, phone, username, password, role) VALUES (?, ?, ?, ?, ?)",
                   (name, phone, username, password, 'user'))
        db.commit()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return jsonify({"status": "success", "user": dict(user)}), 201
    except sqlite3.IntegrityError as e:
        return jsonify({"status": "fail", "message": str(e)}), 400

@app.route('/api/transactions/<int:user_id>', methods=['GET'])
def api_transactions(user_id):
    db = get_db()
    transactions = db.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY date DESC", (user_id,)).fetchall()
    return jsonify([dict(tx) for tx in transactions]), 200

if __name__ == '__main__':
    app.run(debug=True)
