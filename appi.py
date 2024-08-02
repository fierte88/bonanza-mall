from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def home():
    return "Bienvenue sur Bonanza Mall!"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        
        return f'Inscription réussie pour {firstname} {lastname} avec email {email}'

    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)