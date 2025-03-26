from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv  # Importation de dotenv pour charger le fichier .env
import logging  


class SignupForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired(), Length(min=8)])
    nom = StringField('Nom', validators=[DataRequired()])
    prenom = StringField('Prénom', validators=[DataRequired()])
    ville = StringField('Ville', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])

class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])


# Charger les variables d'environnement depuis le fichier .env
load_dotenv()

app = Flask(__name__, static_folder='static')

# Configuration de l'URI de la base de données et de la clé secrète
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///velette.db')  # Utilisation de la variable d'environnement
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))  # Utilisation de la variable d'environnement ou d'une clé aléatoire si elle n'est pas définie

# Initialisation de la base de données et de la gestion des sessions utilisateurs
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# Initialisation du logging
logging.basicConfig(filename='app.log', level=logging.ERROR)

# Modèle pour les utilisateurs
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    ville = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')  # Ajout du rôle de l'utilisateur

# Modèle de données pour les réservations
class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    heure = db.Column(db.String(20), nullable=False)
    depart = db.Column(db.String(100), nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    user = db.relationship('User', backref=db.backref('reservations', lazy=True))

# Création des tables dans la base de données
with app.app_context():
    db.create_all()

# Données pour les abonnements
abonnements = {
    "Mensuel": 15,
    "Trimestriel": 45,
    "Annuel": 135
}

# Charge un utilisateur à partir de la base de données
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/abonnement')
def abonnement():
    return render_template('abonnement.html', abonnements=abonnements)

@app.route('/reserver', methods=["GET", "POST"])
@login_required
def reserver():
    if request.method == "POST":
        nom = request.form["nom et prenom"]
        date = request.form["date"]
        heure = request.form["heure"]
        adresse = request.form["adresse domicile"]
        ecole = request.form["ecole"]

        # Crée la réservation et associe-la à l'utilisateur actuel
        reservation = Reservation(nom=nom, date=date, heure=heure, adresse=adresse, ecole=ecole, user_id=current_user.id)
        db.session.add(reservation)
        db.session.commit()

        flash('Réservation réussie!', 'success')
        return redirect(url_for("home"))

    return render_template('reserver.html')

@app.route('/reservations')
@login_required
def liste_reservations():
    reservations = Reservation.query.filter_by(user_id=current_user.id).paginate(page=request.args.get('page', 1, type=int), per_page=5)
    return render_template('reservations.html', reservations=reservations)

@app.route('/supprimer_reservation/<int:id>', methods=["POST"])
@login_required
def supprimer_reservation(id):
    reservation = Reservation.query.get(id)
    if reservation:
        db.session.delete(reservation)
        db.session.commit()
        flash('Réservation supprimée avec succès!', 'success')
    else:
        flash('Réservation introuvable.', 'danger')
    return redirect(url_for("liste_reservations"))

@app.route('/signup', methods=["GET", "POST"])
def signup():
    form = SignupForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        nom = form.nom.data
        prenom = form.prenom.data
        ville = form.ville.data
        email = form.email.data

        # Vérifier si l'utilisateur ou l'email existe déjà
        if User.query.filter_by(username=username).first():
            flash('Ce nom d\'utilisateur existe déjà!', 'danger')
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash('Cet e-mail est déjà utilisé!', 'danger')
            return redirect(url_for('signup'))

        # Hachage du mot de passe
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, password=hashed_password, nom=nom, prenom=prenom, ville=ville, email=email)
        db.session.add(new_user)
        db.session.commit()

        flash('Inscription réussie! Vous pouvez maintenant vous connecter.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        # Récupère les informations du formulaire
        username = form.username.data
        password = form.password.data
        
        # Recherche l'utilisateur dans la base de données
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            # Si l'utilisateur existe et le mot de passe est correct, connecter l'utilisateur
            login_user(user)
            flash('Connexion réussie!', 'success')

            # Redirige l'utilisateur vers la page demandée ou la page d'accueil
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))  # 'index' est la page d'accueil

        else:
            # Si l'utilisateur n'existe pas ou si le mot de passe est incorrect
            flash('Nom d\'utilisateur ou mot de passe incorrect.', 'danger')

    return render_template('login.html', form=form)

@app.route('/profil')
@login_required
def profil():
    reservations = Reservation.query.filter_by(user_id=current_user.id).all()
    return render_template('profil.html', reservations=reservations)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Déconnexion réussie!', 'success')
    return redirect(url_for('home'))

# Gestion des erreurs
@app.errorhandler(404)
def page_not_found(e):
    app.logger.error(f"Page non trouvée: {str(e)}")  # Ajout du logging
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    app.logger.error(f"Erreur interne: {str(e)}")  # Ajout du logging
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
