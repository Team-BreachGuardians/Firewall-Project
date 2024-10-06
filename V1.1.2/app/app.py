from flask import Flask, request, redirect, url_for, render_template, jsonify
import mysql.connector
import re

app = Flask(__name__)

db_config = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': 'pbian12345',
    'database': 'firewall_complete_db'
}

def get_db_connection():
    conn = mysql.connector.connect(**db_config)
    return conn

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    if not email or not validate_email(email):
        return "<script>alert('Invalid email format.'); window.location.href = '/';</script>"

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT password FROM login_info WHERE email = %s', (email,))
    user = cursor.fetchone()
    conn.close()

    if user and user['password'] == password:
        return redirect(url_for('mainpage'))
    else:
        return "<script>alert('Invalid email or password. Please try again.'); window.location.href = '/';</script>"

@app.route('/mainpage')
def mainpage():
    return render_template('Home.html')

@app.route('/features')
def features():
    return render_template('feature.html')

@app.route('/policies')
def policies():
    return render_template('policies.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/dashboard')
def dashboard():
    return render_template('Dashboard.html')

@app.route('/verify-password', methods=['POST'])
def verify_password():
    password = request.form['password']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT password FROM login_info WHERE email = %s', ('your_email@example.com',))
    user = cursor.fetchone()
    conn.close()

    if user and user['password'] == password:
        return "true"
    else:
        return "false"

def validate_email(email):
    email_regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.match(email_regex, email)

if __name__ == '__main__':
    app.run(debug=True, port=3000)
