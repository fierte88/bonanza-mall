from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def home():
    return 'BONANZA MALL'

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        return f'User {username} signed up successfully!'
    return render_template('signup.html')

if __name__ == '__main__':
    app.run(debug=True)