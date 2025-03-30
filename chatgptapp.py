from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'your_secret_key'

users = {
    "testuser": {"password": "password123", "name": "Test User"}
}

@app.route('/')
def home():
    return 'Welcome to the Home Page!'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users.get(username)
        if user and user['password'] == password:
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            return "Invalid username or password", 401

    return '''
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <button type="submit">Login</button>
        </form>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        username = session['user']
        return f"Hello, {username}! Welcome to your dashboard."
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)
