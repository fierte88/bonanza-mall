from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

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
    inviter = db.relationship('User', remote_side=[id], backref='invitees')
    last_task_time = db.Column(db.DateTime, nullable=True)
    complete_tasks = db.Column(db.Integer, default=0)
    team_commission = db.Column(db.Float, default=0.0)
    withdrawable_balance = db.Column(db.Float, default=0.0)
    general_balance = db.Column(db.Float, default=0.0)
    withdrawals = db.relationship('Withdrawal', backref='user', lazy=True) 
       
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()        