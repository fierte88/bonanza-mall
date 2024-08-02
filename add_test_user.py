# add_test_user.py

from app import app, db, User
import bcrypt

def add_test_user():
    with app.app_context():
        # Supprimer l'utilisateur de test s'il existe déjà
        existing_user = User.query.filter_by(username='testuser').first()
        if existing_user:
            db.session.delete(existing_user)
            db.session.commit()

        # Hachage du mot de passe avec bcrypt
        password = 'testpassword'
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        test_user = User(
            username='testuser',
            firstname='Test',
            lastname='User',
            email='testuser@example.com',
            password=hashed_password,
            invitation_link='test-invitation-link'
        )
        # Ajout de l'utilisateur à la base de données
        db.session.add(test_user)
        db.session.commit()

        print("Utilisateur de test ajouté.")

# Appel de la fonction pour ajouter l'utilisateur de test
if __name__ == '__main__':
    add_test_user()