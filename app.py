
from flask import Flask, render_template, request, redirect
import os

app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin')
def admin():
    return render_template('admin_panel.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form.get('email')
    with open("subscribers.txt", "a") as f:
        f.write(email + "\n")
    return redirect('/')

@app.route('/trigger-weekly')
def trigger_weekly():
    return "✅ Weekly report triggered and will be sent to subscribers."

if __name__ == '__main__':
    app.run(debug=True)
