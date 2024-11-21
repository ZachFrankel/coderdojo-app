from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from datetime import datetime

import uuid
import sqlite3
import bcrypt

app = Flask(__name__)
app.config.from_object('config.Config')
mail = Mail(app)

def is_logged_in():
    return 'user_id' in session

def is_admin():
    if not is_logged_in():
        pass
    else:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (session['email'],))
        user = cursor.fetchone()
        close_db_connection(conn)

        return user['admin']

def get_db_connection():
    conn = sqlite3.connect(r'pb_data\data.db')
    conn.row_factory = sqlite3.Row
    return conn

def close_db_connection(conn):
    conn.close()

@app.route('/')
def home():
    return render_template('home.html', is_logged_in=is_logged_in, is_admin=is_admin)

@app.route('/about')
def about():
    return render_template('about.html', is_logged_in=is_logged_in, is_admin=is_admin)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not is_logged_in():
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))
    
    if not is_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    close_db_connection(conn)

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        title = request.form.get('title')
        desc = request.form.get('desc')
        event_date = request.form.get('event_date')
        location = request.form.get('location')
        max_p = request.form.get('max_p')
        action = request.form.get('action')

        dt = datetime.strptime(event_date, "%Y-%m-%dT%H:%M")
        event_date = dt.strftime("%Y-%m-%d %H:%M:%S.000Z")

        conn = get_db_connection()
        if action == 'set_admin':
            conn.execute('UPDATE users SET admin = 1 WHERE id = ?', (user_id,))
            flash('Admin granted.', 'success')
        elif action == 'revoke_admin':
            conn.execute('UPDATE users SET admin = 0 WHERE id = ?', (user_id,))
            flash('Admin revoked.', 'success')
        elif action == 'add_event':
            conn.execute('INSERT INTO events (title, desc, event_date, location, max_participants) VALUES (?, ?, ?, ?, ?)',
                          (title, desc, event_date, location, max_p))
            flash('Event Added', 'success')

        conn.commit()
        close_db_connection(conn)
        return redirect(url_for('admin'))

    return render_template('admin.html', users=users, is_logged_in=is_logged_in, is_admin=is_admin)

@app.route('/events')
def events():
    conn = get_db_connection()
    events = conn.execute('SELECT * FROM events').fetchall()
    conn.close()

    return render_template('events.html', is_logged_in=is_logged_in, is_admin=is_admin, events=events)

@app.route('/admin/remove_event/<event_id>', methods=['POST'])
def remove_event(event_id):
    if is_admin():
        conn = get_db_connection()
        conn.execute('DELETE FROM events WHERE id = ?', (event_id,))
        conn.commit()
        conn.close()

        flash('Event Deleted.', 'success')
        return redirect(url_for('events'))
    else:
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()
       
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()
       
        if existing_user:
            flash('Email already registered. Please use a different email or login.', 'danger')
            conn.close()
            return redirect(url_for('register'))
        
        cursor.execute('INSERT INTO users (username, email, password, confirmed, admin) VALUES (?, ?, ?, ?, ?)',
                       (username, email, hashed_password, 0, 0))
        conn.commit()
        close_db_connection(conn)

        token = str(uuid.uuid4().hex)
        link = url_for('auth_confirm', token=token, _external=True)

        session[token] = email

        msg = Message('confirm test', sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[email])
        msg.body = f'link: {link}'
        mail.send(msg)

        print('')
        print(f"debug: {link}")
        print(f"debug: {email}")
        print('')

        flash('A confirmation email has been sent. Please check your inbox.', 'info')
        return redirect(url_for('login'))
    return render_template('register.html', is_logged_in=is_logged_in, is_admin=is_admin)

def send_reset_email_to_user(email):
    token = str(uuid.uuid4().hex)
    link = url_for('reset_password', token=token, _external=True)
    
    session['reset_token'] = token
    session['reset_email'] = email

    print('')
    print(f"debug: {link}")
    print(f"debug: {email}")
    print('')
    
    msg = Message('reset email', sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[email])
    msg.body = f'{link}'
    mail.send(msg)

@app.route('/auth/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        close_db_connection(conn)
        
        if user:
            send_reset_email_to_user(email)
            flash('A reset email has been sent. Please check your inbox.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Invalid email address.', 'danger')
            return redirect(url_for('forgot_password'))
    
    return render_template('forgotPassword.html', is_logged_in=is_logged_in, is_admin=is_admin)

@app.route('/auth/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if token != session.get('reset_token'):
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['nPassword']
        confirm_password = request.form['cPassword']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, session['reset_email']))
        conn.commit()
        close_db_connection(conn)

        session.pop('reset_token', None)
        session.pop('reset_email', None)
        
        flash('Your password has been successfully reset.', 'success')
        return redirect(url_for('login'))

    return render_template('resetPassword.html', token=token, is_logged_in=is_logged_in, is_admin=is_admin)

@app.route('/booking/create/<event_id>', methods=['GET', 'POST'])
def create_booking(event_id):
    if not is_logged_in():
        flash('Must be logged in to perform this action.', 'danger')
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO bookings (userID, eventID, status) VALUES (?, ?, ?)',
                    (session['user_id'], event_id, 'placeholder_debug'))
    conn.commit()
    conn.close()

    flash(f'Successfully booked event {event_id}', 'success')
    return redirect(url_for('dashboard'))

@app.route('/booking/delete/<booking_id>', methods=['GET', 'POST'])
def cancel_booking(booking_id):
    if not is_logged_in():
        flash('Must be logged in to perform this action.', 'danger')
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT userID from bookings WHERE id = ?', (booking_id,))
    id_check = cursor.fetchone()
    id_check = id_check['userID']

    if id_check != session['user_id']:
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    conn.execute('DELETE FROM bookings WHERE id = ?', (booking_id,))
    conn.commit() 
    conn.close()

    flash('Cancelled Booking (Future: Add email confirmation for cancellation & make sure the user is same as userID for the id).', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        flash('Login to access this page.', 'warning')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT bookings.*, events.title, events.desc, events.event_date, events.location
        FROM bookings
        JOIN events ON bookings.eventID = events.id
        WHERE bookings.userID = ?
    ''', (session['user_id'],)) # i totally wrote this query as i totally understand it
    bookings = cursor.fetchall()
    close_db_connection(conn)

    return render_template('dashboard.html', is_logged_in=is_logged_in, is_admin=is_admin, bookings=bookings)

@app.route('/auth/confirm/<token>')
def auth_confirm(token):
    email = session.pop(token, None)

    if email:
        conn = get_db_connection()
        conn.execute('UPDATE users SET confirmed = 1 WHERE email = ?', (email,))
        conn.commit()
        close_db_connection(conn)

        flash('confirmed email, login now', 'success')
        return redirect(url_for('login'))
    else:
        flash('Link is invalid or has expired.', 'danger')
        return redirect(url_for('register'))

@app.route('/auth/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        close_db_connection(conn)

        if user:
            # chatgpt magic
            password_bytes = password.encode('utf-8')

            stored_password_bytes = user['password']
            if isinstance(stored_password_bytes, str):
                stored_password_bytes = stored_password_bytes.encode('utf-8')
            #end of chatgpt magic
            if bcrypt.checkpw(password_bytes, stored_password_bytes):
                if user['confirmed']:
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['email'] = user['email']
                    flash('You are now logged in', 'success')
                    return redirect(url_for('home'))
                else:
                    flash('A confirmation email has been sent. Please check your inbox.', 'info')
                    return redirect(url_for('login'))
            else:
                flash('Login unsuccessful. Please check email and password.', 'danger')
                return redirect(url_for('login'))

    return render_template('login.html', is_logged_in=is_logged_in)

@app.route('/auth/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)