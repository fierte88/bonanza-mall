from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from flask import send_from_directory
from flask_migrate import Migrate
from config import Config  # Importer la classe Config
import os
from flask_bcrypt import Bcrypt
from functools import wraps
import uuid
from datetime import datetime, timedelta
import pytz
import logging

app = Flask(__name__)
app.config.from_object(Config)  # Charger les configurations depuis Config

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

from models import User

app.config['UPLOAD_FOLDER'] = 'uploads_file/'
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

logging.basicConfig(level=logging.DEBUG)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    firstname = db.Column(db.String(80), nullable=False)
    lastname = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    withdrawable_balance = db.Column(db.Float, default=0.0)
    invitation_link = db.Column(db.String(200), unique=True, nullable=True)
    inviter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    inviter = db.relationship('User', remote_side=[id], backref='invitees', foreign_keys=[inviter_id])
    last_task_time = db.Column(db.DateTime, nullable=True)
    complete_tasks = db.Column(db.Integer, default=0)
    team_commission = db.Column(db.Float, default=0.0)
    general_balance = db.Column(db.Float, default=0.0)
    withdrawals = db.relationship('Withdrawal', backref='user', lazy=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    subordinates = db.relationship('User', backref=db.backref('sponsor', remote_side=[id]), lazy=True, foreign_keys=[sponsor_id])

    def __repr__(self):
        return '<User %r>' % self.username

class Recharge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)  # Montant de la recharge
    transaction_hash = db.Column(db.String(200), nullable=True)  # Champ optionnel pour le hash de la transaction
    phone_number = db.Column(db.String(15), nullable=True)  # Numéro de téléphone pour MTN
    screenshot_path = db.Column(db.String(200), nullable=True)  # Chemin vers la capture d'écran
    status = db.Column(db.String(50), default='Pending')  # Statut de la recharge

    def _repr_(self):
        return f'<Recharge {self.id}: {self.amount} - {self.status}>'

class Withdrawal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    withdrawal_address = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default='Pending')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    completed = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('tasks', lazy=True))
    
def calculate_commission(self):
    """
    Calculer la commission pour les tâches effectuées par cet utilisateur.
    """
    return self.complete_tasks * 0.025  # Exemples de calcul de commission pour les tâches
    
def total_tasks_commission(self):
    total_commission = 0.0

    # Calculer les commissions des membres directs
    for invitee in self.invitees:
        # Commission pour le mentor de premier niveau
        total_commission += invitee.calculate_commission() * 0.08

    # Calculer les commissions des membres de deuxième génération
    for invitee in self.invitees:
        for second_gen in invitee.invitees:
            # Commission pour le mentor de deuxième niveau
            total_commission += second_gen.calculate_commission() * 0.05

    # Calculer les commissions des membres de troisième génération
    for invitee in self.invitees:
        for second_gen in invitee.invitees:
            for third_gen in second_gen.invitees:
                # Commission pour le mentor de troisième niveau
                total_commission += third_gen.calculate_commission() * 0.01

    return total_commission

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash("Vous devez être connecté pour accéder à cette page.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap

@app.route('/home')
def home():
    return render_template('home.html')
    
@app.route('/uploads/<filename>')
def uploads_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)    
    
@app.route('/')
def index():
    return redirect(url_for('home'))    
    
@app.route('/about')
def about():
    return render_template('about.html')    

import random
import string

def generate_invitation_code(length=8):
    """Génère un code d'invitation aléatoire de longueur spécifiée."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))
    invitation_code = generate_invitation_code()
    print(f"Code d'invitation généré : {invitation_code}")
# Supposons que vous ayez un utilisateur avec un code d'invitation
    new_user = User(username='testuser', password='password123', invitation_link=invitation_code)
    db.session.add(new_user)
    db.session.commit()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        email = request.form.get('email')
        password = request.form.get('password')
        password_repeat = request.form.get('password_repeat')
        invitation_code = request.form.get('invitation_code')

        if not all([username, firstname, lastname, email, password, password_repeat]):
            flash("Veuillez remplir tous les champs.")
            return redirect(url_for('register'))

        if password != password_repeat:
            flash("Les mots de passe ne correspondent pas.")
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash("Cet utilisateur existe déjà. Veuillez choisir un autre email.")
            return redirect(url_for('register'))

        inviter = None
        if invitation_code:
            # Utiliser 'invitation_link' si c'est le nom correct dans le modèle User
            inviter = User.query.filter_by(invitation_link=invitation_code).first()
            if not inviter:
                flash("Le code d'invitation est invalide.")
                return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_invitation_code = generate_invitation_code()  # Générer un nouveau code d'invitation court

        try:
            new_user = User(
                username=username,
                firstname=firstname, 
                lastname=lastname, 
                email=email, 
                password=hashed_password,
                invitation_link=new_invitation_code,  # Utiliser l'attribut correct
                inviter_id=inviter.id if inviter else None
            )
            db.session.add(new_user)
            db.session.commit()

            if inviter:
                inviter.team_commission = (inviter.team_commission or 0) + 0.4
                db.session.commit()

            session['user_id'] = new_user.id
            flash("Inscription réussie ! Vous êtes maintenant connecté.")
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            flash(f"Une erreur est survenue lors de l'inscription. Veuillez réessayer. {str(e)}")
            return redirect(url_for('register'))

    return render_template('register.html')
    
@app.route('/invite/<invitation_code>')
def invite(invitation_code):
    return render_template('register.html', invitation_code=invitation_code)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        logging.debug(f"Attempting to log in with email: {email}")
        user = User.query.filter_by(email=email).first()

        if user:
            # Vérification du mot de passe avec bcrypt
            if bcrypt.check_password_hash(user.password, password):
                logging.debug(f"User found: {user.username}")
                session['user_id'] = user.id
                flash("Connexion réussie !")
                return redirect(url_for('home'))
            else:
                flash("Email ou mot de passe incorrect.")
                logging.debug("Password does not match.")
        else:
            flash("Email ou mot de passe incorrect.")
            logging.debug("User not found.")

        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    recharges = Recharge.query.filter_by(user_id=user.id).all()
    withdrawals = Withdrawal.query.filter_by(user_id=user.id).all()
    return render_template('profile.html', user=user, recharges=recharges, withdrawals=withdrawals)

@app.route('/recharge', methods=['GET', 'POST'])
@login_required
def recharge():
    if request.method == 'POST':
        amount = request.form.get('transaction-amount')
        transaction_hash = request.form.get('transaction-hash')
        screenshot = request.files.get('transaction-screenshot')

        if not amount or not transaction_hash or not screenshot:
            flash("Veuillez remplir tous les champs.")
            return redirect(url_for('recharge'))

        # Sauvegarde de la capture d'écran
        screenshot_filename = secure_filename(screenshot.filename)
        screenshot_path = os.path.join(app.config['UPLOAD_FOLDER'], screenshot_filename)
        screenshot.save(screenshot_path)

        user_id = session.get('user_id')

        try:
            new_recharge = Recharge(
                user_id=user_id,
                amount=float(amount),
                transaction_hash=transaction_hash,
                screenshot_path=screenshot_filename  # Enregistrer seulement le nom du fichier
            )
            db.session.add(new_recharge)
            db.session.commit()
            flash("Votre demande de recharge est en attente de vérification et sera créditée sur votre compte dans peu de minutes.")
        except Exception as e:
            db.session.rollback()
            flash("Une erreur est survenue lors de la demande de recharge. Veuillez réessayer.")

        return redirect(url_for('recharge'))

    # Récupération de l'historique des recharges
    user_id = session.get('user_id')
    recharges = Recharge.query.filter_by(user_id=user_id).all()

    return render_template('recharge.html', crypto_address="TTMKMrrfNQPXYhiNS1mSBpX6Pgu2wzpJeZ", recharges=recharges)
    
@app.route('/recharge_mtn', methods=['GET', 'POST'])
@login_required
def recharge_mtn():
    if request.method == 'POST':
        phone = request.form.get('transaction-phone')
        amount = request.form.get('transaction-amount')
        screenshot = request.files.get('transaction-screenshot')

        # Validation des champs
        if not phone or not amount or not screenshot:
            flash("Veuillez remplir tous les champs.")
            return redirect(url_for('recharge_mtn'))

        if not re.match(r'^\+\d{1,3}\d{9}$', phone):  # Modifiez selon le format de votre numéro de téléphone
            flash("Veuillez entrer un numéro de téléphone valide.")
            return redirect(url_for('recharge_mtn'))

        try:
            amount = float(amount)
            if amount <= 0:
                flash("Le montant doit être supérieur à zéro.")
                return redirect(url_for('recharge_mtn'))
        except ValueError:
            flash("Veuillez entrer un montant valide.")
            return redirect(url_for('recharge_mtn'))

        # Sauvegarde de la capture d'écran
        screenshot_filename = secure_filename(screenshot.filename)
        screenshot_path = os.path.join(app.config['UPLOAD_FOLDER'], screenshot_filename)

        # Vérifiez que le dossier existe
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        screenshot.save(screenshot_path)

        user_id = session.get('user_id')

        try:
            new_recharge = Recharge(
                user_id=user_id,
                amount=amount,
                phone_number=phone,
                screenshot_path=screenshot_filename,  # Enregistrer seulement le nom du fichier
                status='Pending'  # Statut par défaut
            )
            db.session.add(new_recharge)
            db.session.commit()
            flash("Votre demande de recharge MTN a été soumise avec succès et est en attente de vérification.")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de la soumission de la demande de recharge : {e}")  # Enregistrement de l'erreur dans les logs
            flash("Une erreur est survenue lors de la demande de recharge. Veuillez réessayer.")

        return redirect(url_for('recharge_mtn'))

    # Récupération de l'historique des recharges
    user_id = session.get('user_id')
    recharges = Recharge.query.filter_by(user_id=user_id).all()

    return render_template('recharge_mtn.html', recharges=recharges)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory('uploads_file', filename)
    

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    if request.method == 'POST':
        withdrawal_amount = request.form.get('withdrawal-amount')
        withdrawal_address = request.form.get('withdrawal-address')

        if not withdrawal_amount or not withdrawal_address:
            flash("Montant et adresse de retrait sont requis", "danger")
            return redirect(url_for('withdraw'))

        try:
            withdrawal_amount = float(withdrawal_amount)
        except ValueError:
            flash("Montant de retrait invalide", "danger")
            return redirect(url_for('withdraw'))

        if 'user_id' not in session:
            flash("Vous devez être connecté pour effectuer un retrait", "danger")
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])

        if user.withdrawable_balance is None:
            user.withdrawable_balance = 0.0

        if user.general_balance is None:
            user.general_balance = 0.0

        # Debugging: Print balances to the console
        print(f"User ID: {user.id}")
        print(f"Withdrawable Balance (before): {user.withdrawable_balance}")
        print(f"General Balance (before): {user.general_balance}")
        print(f"Requested Withdrawal Amount: {withdrawal_amount}")

        if user.withdrawable_balance < withdrawal_amount:
            flash("Solde insuffisant pour effectuer le retrait", "danger")
            return redirect(url_for('withdraw'))

        # Deduct the withdrawal amount from both balances
        user.withdrawable_balance -= withdrawal_amount
        user.general_balance -= withdrawal_amount

        # Debugging: Print balances to the console after deduction
        print(f"Withdrawable Balance (after): {user.withdrawable_balance}")
        print(f"General Balance (after): {user.general_balance}")

        new_withdrawal = Withdrawal(
            user_id=user.id,
            amount=withdrawal_amount,
            withdrawal_address=withdrawal_address,
            status='En cours'
        )
        db.session.add(new_withdrawal)
        db.session.commit()

        # Debugging: Confirm commit
        print("Withdrawal transaction committed.")

        flash("Demande de retrait soumise avec succès", "success")
        return redirect(url_for('withdraw'))

    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        withdrawals = Withdrawal.query.filter_by(user_id=user.id).all()
    else:
        withdrawals = []

    return render_template('withdraw.html', user=user, withdrawals=withdrawals)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        new_password_repeat = request.form.get('new_password_repeat')

        if not current_password or not new_password or not new_password_repeat:
            flash("Veuillez remplir tous les champs.")
            return redirect(url_for('change_password'))

        user = User.query.get(session['user_id'])

        if not check_password_hash(user.password, current_password):
            flash("Le mot de passe actuel est incorrect.")
            return redirect(url_for('change_password'))

        if new_password != new_password_repeat:
            flash("Les nouveaux mots de passe ne correspondent pas.")
            return redirect(url_for('change_password'))

        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()

        flash("Votre mot de passe a été changé avec succès.")
        return redirect(url_for('profile'))

    return render_template('change_password.html')

@app.route('/change_address', methods=['GET', 'POST'])
@login_required
def change_address():
    if request.method == 'POST':
        new_address = request.form.get('new_address')
        confirm_new_address = request.form.get('confirm_new_address')

        if not new_address or not confirm_new_address:
            flash("Veuillez remplir tous les champs.")
            return redirect(url_for('change_address'))

        if new_address != confirm_new_address:
            flash("Les nouvelles adresses ne correspondent pas.")
            return redirect(url_for('change_address'))

        user = User.query.get(session['user_id'])
        user.address = new_address
        db.session.commit()

        flash("Votre adresse a été changée avec succès.")
        return redirect(url_for('profile'))

    return render_template('change_address.html')
    
@app.route('/complete_task/<int:task_id>', methods=['POST'])
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.completed:
        flash('Task already completed', 'warning')
        return redirect(url_for('tasks'))

    task.completed = True
    db.session.commit()

    user = User.query.get(task.user_id)
    commission_amount = task.commission

    # Ajouter la commission au solde général et retirable de l'utilisateur
    user.balance += commission_amount
    user.withdrawable_balance += commission_amount

    # Mettre à jour les soldes des parrains selon la structure de commission
    update_sponsor_commissions(user, commission_amount)

    db.session.commit()
    flash('Task completed and commission added', 'success')
    return redirect(url_for('tasks'))

def update_sponsor_commissions(user, commission_amount):
    levels = [0.08, 0.05, 0.01]  # Les pourcentages pour les niveaux 1, 2 et 3
    current_user = user
    for level in levels:
        if current_user.sponsor_id:
            sponsor = User.query.get(current_user.sponsor_id)
            commission = commission_amount * level
            sponsor.balance += commission
            sponsor.withdrawable_balance += commission
            sponsor.team_commission += commission
            current_user = sponsor
        else:
            break    
    
@app.route('/tasks', methods=['GET', 'POST'])
@login_required
def tasks():
    user_id = session['user_id']
    user = User.query.get(user_id)
    now = datetime.now(pytz.timezone('Africa/Abidjan'))

    can_do_task = user.balance >= 10

    if request.method == 'POST':
        if user.balance < 10:
            flash("Vous devez avoir au moins 10 USDT sur votre compte pour effectuer des tâches.")
            return redirect(url_for('tasks'))

        if user.balance is None:
            user.balance = 0.0
        if user.withdrawable_balance is None:
            user.withdrawable_balance = 0.0

        last_task_time = user.last_task_time
        if last_task_time and last_task_time.date() == now.date():
            flash("Vous avez déjà effectué une tâche aujourd'hui. Revenez demain.")
            return redirect(url_for('tasks'))

        task_earnings = user.balance * 0.025

        try:
            new_task = Task(user_id=user_id, amount=task_earnings, completed=True, timestamp=now)
            db.session.add(new_task)

            user.balance += task_earnings
            user.withdrawable_balance += task_earnings
            user.last_task_time = now
            db.session.commit()

            flash(f"Félicitations! Vous avez gagné {task_earnings:.2f} USDT.")
        except Exception as e:
            db.session.rollback()
            print(f"Error: {e}")
            flash("Une erreur est survenue lors de la tâche. Veuillez réessayer.")

        return redirect(url_for('tasks'))

    return render_template('tasks.html', can_do_task=can_do_task)

@app.route('/check_balance', methods=['GET'])
@login_required
def check_balance():
    user_id = session['user_id']
    user = User.query.get(user_id)
    balance = user.balance if user.balance else 0.0
    return jsonify({"balance": balance})

@app.route('/update_balance', methods=['GET'])
@login_required
def update_balance():
    user_id = session['user_id']
    user = User.query.get(user_id)
    task_earnings = user.balance * 0.025
    user.balance += task_earnings
    user.withdrawable_balance += task_earnings
    db.session.commit()
    return jsonify({"message": "Balances updated", "balance": user.balance, "withdrawable_balance": user.withdrawable_balance})
    
   
@app.route('/team')
@login_required
def team():
    user_id = session['user_id']
    user = User.query.get(user_id)

    if user is None:
        flash("Utilisateur non trouvé.")
        return redirect(url_for('login'))

    # Récupérer les membres directs de l'utilisateur (Niveau 1)
    level_1_members = user.invitees

    # Calculer les commissions pour le Niveau 1
    level_1_commission = 0
    for member in level_1_members:
        if hasattr(member, 'total_tasks_commission'):
            tasks_commission = member.total_tasks_commission()
            level_1_commission += 0.08 * tasks_commission

    # Récupérer les membres de deuxième génération (Niveau 2)
    level_2_members = []
    for member in level_1_members:
        level_2_members.extend(member.invitees)

    # Calculer les commissions pour le Niveau 2
    level_2_commission = 0
    for member in level_2_members:
        if hasattr(member, 'total_tasks_commission'):
            tasks_commission = member.total_tasks_commission()
            level_2_commission += 0.05 * tasks_commission

    # Récupérer les membres de troisième génération (Niveau 3)
    level_3_members = []
    for member in level_2_members:
        level_3_members.extend(member.invitees)

    # Calculer les commissions pour le Niveau 3
    level_3_commission = 0
    for member in level_3_members:
        if hasattr(member, 'total_tasks_commission'):
            tasks_commission = member.total_tasks_commission()
            level_3_commission += 0.01 * tasks_commission

    # Calculer le total des commissions
    total_commission = level_1_commission + level_2_commission + level_3_commission

    # Calculer le nombre total de membres de l'équipe
    team_size = len(level_1_members) + len(level_2_members) + len(level_3_members)

    return render_template('team.html', 
                           user=user, 
                           level_1_members=level_1_members,
                           level_2_members=level_2_members,
                           level_3_members=level_3_members,
                           total_commission=total_commission,
                           team_size=team_size)

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    flash("Vous êtes maintenant déconnecté.")
    return redirect(url_for('login'))
    
    
if __name__ == '__main__':
   app.run()