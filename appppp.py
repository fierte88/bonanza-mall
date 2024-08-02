from flask import Flask, render_template, request

app = Flask(__name__)
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        
        return f'Inscription réussie pour {username} avec l\'email {email}'

  return render_template('signup.html')

if __name__ == '__main__':
    app.run(debug=True)