import sqlite3
import os
import re
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ============================================================
# CONFIGURATION DE L'APPLICATION
# ============================================================

app = Flask(__name__)
app.secret_key = "agora_secure_secret_key_2026"

# Chemin vers la base de données partagée
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "database", "agora.db")

# Dossier pour les photos de profil
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ============================================================
# CONNEXION À LA BASE DE DONNÉES
# ============================================================

def get_db():
    """Retourne une connexion à la base de données."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        # Activation des clés étrangères
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(error):
    """Ferme la connexion en fin de requête."""
    db = g.pop("db", None)
    if db is not None:
        db.close()

def allowed_file(filename):
    """Vérifie que l'extension du fichier est autorisée."""
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ============================================================
# ZONE DE TRAÇABILITÉ SQL — VERSION SÉCURISÉE
# ============================================================

sql_trace = []

def execute_secure(query, params=(), fetchone=False,
                   fetchall=False, commit=False):
    """
    Exécute une requête SQL sécurisée via requêtes paramétrées.
    Les paramètres sont toujours passés séparément — jamais
    concaténés dans la requête. SQLite les traite comme des
    données pures, jamais comme du code SQL.
    """
    db = get_db()
    sql_trace.append(f"[SÉCURISÉ] {query} | params: {params}")

    try:
        cursor = db.execute(query, params)
        if commit:
            db.commit()
            return None
        if fetchone:
            return cursor.fetchone()
        if fetchall:
            return cursor.fetchall()
    except sqlite3.Error as e:
        # En version sécurisée on ne retourne PAS le message d'erreur
        # à l'utilisateur — on le logue uniquement côté serveur
        sql_trace.append(f"[ERREUR INTERNE — non exposée] {str(e)}")
        return None

# ============================================================
# VALIDATION DES ENTRÉES
# ============================================================

def valider_email(email):
    """
    Valide le format d'un email via expression régulière.
    Contre-mesure : rejette toute saisie ne ressemblant pas
    à un email avant même de toucher à la base de données.
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def valider_pseudo(pseudo):
    """
    Valide le pseudo — uniquement lettres, chiffres, underscore
    et tiret. Rejette tout caractère SQL suspect.
    Contre-mesure : ' -- ; = sont impossibles dans un pseudo valide.
    """
    pattern = r'^[a-zA-Z0-9_-]{3,30}$'
    return re.match(pattern, pseudo) is not None

def valider_longueur(texte, max_len=160):
    """Vérifie que le texte ne dépasse pas la longueur maximale."""
    return len(texte) <= max_len

# ============================================================
# DÉCORATEUR DE PROTECTION DES ROUTES
# ============================================================

def login_required(f):
    """Redirige vers la connexion si l'utilisateur n'est pas connecté."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "utilisateur_id" not in session:
            flash("Vous devez être connecté pour accéder à cette page.",
                  "warning")
            return redirect(url_for("connexion"))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================
# VARIABLE DE CONTEXTE GLOBAL
# ============================================================

@app.context_processor
def inject_globals():
    """Injecte current_user et sql_trace dans tous les templates."""
    current_user = None
    if "utilisateur_id" in session:
        current_user = execute_secure(
            "SELECT * FROM utilisateurs WHERE id = ?",
            params=(session["utilisateur_id"],),
            fetchone=True
        )
    return {
        "current_user": current_user,
        "sql_trace": sql_trace
    }

@app.route("/vider-trace")
def vider_trace():
    """Vide la zone de traçabilité SQL."""
    sql_trace.clear()
    return redirect(request.referrer or url_for("fil"))

# ============================================================
# ROUTES D'AUTHENTIFICATION
# ============================================================

@app.route("/")
def index():
    """Redirige vers le fil si connecté, sinon vers la connexion."""
    if "utilisateur_id" in session:
        return redirect(url_for("fil"))
    return redirect(url_for("connexion"))


@app.route("/connexion", methods=["GET", "POST"])
def connexion():
    """
    SÉCURISÉ : Requête paramétrée + validation du format email
    + vérification du mot de passe avec check_password_hash.
    Aucune concaténation — l'email est passé comme paramètre lié.
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        mot_de_passe = request.form.get("mot_de_passe", "")

        # CONTRE-MESURE 1 : Validation du format email
        # Une saisie comme ' OR '1'='1 ne ressemble pas à un email
        # et est rejetée avant même d'atteindre la base de données
        if not valider_email(email):
            flash("Format d'email invalide.", "danger")
            return render_template("connexion.html")

        # CONTRE-MESURE 2 : Requête paramétrée
        # Le ? garantit que email est traité comme une donnée pure
        # Impossible d'y injecter du code SQL
        utilisateur = execute_secure(
            "SELECT * FROM utilisateurs WHERE email = ?",
            params=(email,),
            fetchone=True
        )

        # CONTRE-MESURE 3 : Vérification du mot de passe en Python
        # Indépendante de la requête SQL — ne peut pas être contournée
        # par une injection dans le champ email
        if utilisateur and check_password_hash(
                utilisateur["mot_de_passe"], mot_de_passe):
            session.clear()
            session["utilisateur_id"] = utilisateur["id"]
            session["pseudo"] = utilisateur["pseudo"]
            flash("Connexion réussie. Bienvenue sur Agora !", "success")
            return redirect(url_for("fil"))
        else:
            # Message générique — ne révèle pas si c'est l'email
            # ou le mot de passe qui est incorrect
            flash("Identifiants incorrects. Réessayez.", "danger")

    return render_template("connexion.html")


@app.route("/inscription", methods=["GET", "POST"])
def inscription():
    """
    SÉCURISÉ : Validation stricte des entrées + requêtes paramétrées.
    Le pseudo malveillant comme tsahui'-- est rejeté par la validation
    avant d'atteindre la base — la second-order est impossible.
    """
    if request.method == "POST":
        pseudo = request.form.get("pseudo", "").strip()
        email = request.form.get("email", "").strip()
        mot_de_passe = request.form.get("mot_de_passe", "")

        # CONTRE-MESURE : Validation stricte de chaque champ
        erreurs = []
        if not valider_pseudo(pseudo):
            erreurs.append(
                "Le pseudo ne peut contenir que des lettres, "
                "chiffres, - et _ (3 à 30 caractères)."
            )
        if not valider_email(email):
            erreurs.append("Format d'email invalide.")
        if len(mot_de_passe) < 6:
            erreurs.append(
                "Le mot de passe doit contenir au moins 6 caractères."
            )

        if erreurs:
            for erreur in erreurs:
                flash(erreur, "danger")
            return render_template("inscription.html")

        # Vérification unicité via requête paramétrée
        existant = execute_secure(
            "SELECT id FROM utilisateurs WHERE email = ? OR pseudo = ?",
            params=(email, pseudo),
            fetchone=True
        )
        if existant:
            flash("Cet email ou ce pseudo est déjà utilisé.", "danger")
            return render_template("inscription.html")

        # Gestion photo de profil
        photo = "default.png"
        if "photo_profil" in request.files:
            fichier = request.files["photo_profil"]
            if fichier and fichier.filename != "" \
                    and allowed_file(fichier.filename):
                nom_fichier = secure_filename(fichier.filename)
                fichier.save(os.path.join(
                    app.config["UPLOAD_FOLDER"], nom_fichier))
                photo = nom_fichier

        mot_de_passe_hash = generate_password_hash(mot_de_passe)
        maintenant = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Insertion via requête paramétrée
        execute_secure(
            """INSERT INTO utilisateurs
               (pseudo, email, mot_de_passe, date_inscription)
               VALUES (?, ?, ?, ?)""",
            params=(pseudo, email, mot_de_passe_hash, maintenant),
            commit=True
        )

        flash("Compte créé avec succès. Connectez-vous !", "success")
        return redirect(url_for("connexion"))

    return render_template("inscription.html")


@app.route("/deconnexion")
@login_required
def deconnexion():
    """Déconnecte l'utilisateur et efface la session."""
    session.clear()
    flash("Vous avez été déconnecté.", "info")
    return redirect(url_for("connexion"))

# ============================================================
# ROUTES PRINCIPALES
# ============================================================

@app.route("/fil")
@login_required
def fil():
    """
    SÉCURISÉ : Le paramètre tri est validé contre une liste blanche.
    Seules les valeurs autorisées sont acceptées — toute autre valeur
    est ignorée et remplacée par la valeur par défaut.
    """
    tri = request.args.get("tri", "date_publication")

    # CONTRE-MESURE : Liste blanche des valeurs autorisées
    # Un attaquant ne peut pas injecter RANDOMBLOB ou autre expression
    # car seules ces deux valeurs exactes sont acceptées
    valeurs_autorisees = ["date_publication", "id"]
    if tri not in valeurs_autorisees:
        tri = "date_publication"

    # La requête utilise la valeur validée — pas l'entrée brute
    publications = execute_secure(
        f"""SELECT p.*, u.pseudo, u.photo_profil
            FROM publications p
            JOIN utilisateurs u ON u.id = p.utilisateur_id
            ORDER BY p.{tri} DESC
            LIMIT 20""",
        fetchall=True
    )

    return render_template("fil.html", publications=publications)


@app.route("/publication/<int:pub_id>")
@login_required
def publication(pub_id):
    """
    SÉCURISÉ : pub_id est typé int par Flask — toute valeur non entière
    est rejetée automatiquement avec une erreur 404.
    La requête utilise un paramètre lié — pas de concaténation.
    """
    pub = execute_secure(
        """SELECT p.*, u.pseudo, u.photo_profil
           FROM publications p
           JOIN utilisateurs u ON u.id = p.utilisateur_id
           WHERE p.id = ?""",
        params=(pub_id,),
        fetchone=True
    )

    if not pub:
        flash("Publication introuvable.", "danger")
        return redirect(url_for("fil"))

    commentaires = execute_secure(
        """SELECT c.*, u.pseudo, u.photo_profil
           FROM commentaires c
           JOIN utilisateurs u ON u.id = c.utilisateur_id
           WHERE c.publication_id = ?
           ORDER BY c.date_commentaire ASC""",
        params=(pub_id,),
        fetchall=True
    )

    return render_template(
        "publication.html", pub=pub, commentaires=commentaires
    )


@app.route("/commenter/<int:pub_id>", methods=["POST"])
@login_required
def commenter(pub_id):
    """Ajoute un commentaire — requête paramétrée."""
    contenu = request.form.get("contenu", "").strip()

    if not contenu:
        flash("Le commentaire ne peut pas être vide.", "danger")
        return redirect(url_for("publication", pub_id=pub_id))

    if not valider_longueur(contenu, 500):
        flash("Commentaire trop long.", "danger")
        return redirect(url_for("publication", pub_id=pub_id))

    maintenant = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    execute_secure(
        """INSERT INTO commentaires
           (contenu, date_commentaire, utilisateur_id, publication_id)
           VALUES (?, ?, ?, ?)""",
        params=(contenu, maintenant, session["utilisateur_id"], pub_id),
        commit=True
    )

    return redirect(url_for("publication", pub_id=pub_id))


@app.route("/publier", methods=["POST"])
@login_required
def publier():
    """Publie un message — validation + requête paramétrée."""
    contenu = request.form.get("contenu", "").strip()

    if not contenu:
        flash("La publication ne peut pas être vide.", "danger")
        return redirect(url_for("fil"))

    if not valider_longueur(contenu, 280):
        flash("La publication ne peut pas dépasser 280 caractères.",
              "danger")
        return redirect(url_for("fil"))

    maintenant = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    execute_secure(
        """INSERT INTO publications (contenu, date_publication,
           utilisateur_id) VALUES (?, ?, ?)""",
        params=(contenu, maintenant, session["utilisateur_id"]),
        commit=True
    )

    return redirect(url_for("fil"))


@app.route("/recherche")
@login_required
def recherche():
    """
    SÉCURISÉ : Le paramètre de recherche est passé comme paramètre lié.
    L'injection UNION-based est impossible — SQLite traite la saisie
    comme une donnée pure, jamais comme du code SQL.
    """
    q = request.args.get("q", "").strip()
    resultats = []

    if q:
        # CONTRE-MESURE : Requête paramétrée avec LIKE
        # Le ? englobe automatiquement la valeur entre les %
        # Une payload UNION SELECT est traitée comme du texte littéral
        execute_secure(
            """SELECT id, pseudo, bio, email, photo_profil
               FROM utilisateurs
               WHERE pseudo LIKE ?""",
            params=(f"%{q}%",),
            fetchall=True
        )
        resultats = execute_secure(
            """SELECT id, pseudo, bio, email, photo_profil
               FROM utilisateurs
               WHERE pseudo LIKE ?""",
            params=(f"%{q}%",),
            fetchall=True
        )

    return render_template("recherche.html", resultats=resultats, q=q)    

# ============================================================
# ROUTES DE PROFIL
# ============================================================

@app.route("/profil/<pseudo>")
@login_required
def profil(pseudo):
    """
    SÉCURISÉ : Le pseudo est passé comme paramètre lié.
    L'injection Blind Boolean-based est impossible — la saisie
    est traitée comme une donnée pure par SQLite.
    """
    # CONTRE-MESURE : Validation du format pseudo
    if not valider_pseudo(pseudo):
        flash("Pseudo invalide.", "danger")
        return redirect(url_for("fil"))

    utilisateur = execute_secure(
        "SELECT * FROM utilisateurs WHERE pseudo = ?",
        params=(pseudo,),
        fetchone=True
    )

    if not utilisateur:
        flash("Utilisateur introuvable.", "danger")
        return redirect(url_for("fil"))

    publications = execute_secure(
        """SELECT * FROM publications
           WHERE utilisateur_id = ?
           ORDER BY date_publication DESC""",
        params=(utilisateur["id"],),
        fetchall=True
    )

    stats = execute_secure(
        "SELECT COUNT(*) as total FROM commentaires WHERE utilisateur_id = ?",
        params=(utilisateur["id"],),
        fetchone=True
    )

    return render_template(
        "profil.html",
        utilisateur=utilisateur,
        publications=publications,
        stats=stats
    )


@app.route("/modifier-profil", methods=["GET", "POST"])
@login_required
def modifier_profil():
    """
    SÉCURISÉ : Double protection contre la Second-Order.
    Le pseudo n'est jamais utilisé dans la requête UPDATE —
    on utilise l'ID de session à la place, qui est un entier
    contrôlé par le serveur et non par l'utilisateur.
    La bio et l'email sont également validés avant utilisation.
    """
    utilisateur_id = session["utilisateur_id"]

    if request.method == "POST":
        bio = request.form.get("bio", "").strip()
        email = request.form.get("email", "").strip()

        # CONTRE-MESURE : Validation des entrées
        if not valider_email(email):
            flash("Format d'email invalide.", "danger")
            return redirect(url_for("modifier_profil"))

        if not valider_longueur(bio, 160):
            flash("La bio ne peut pas dépasser 160 caractères.", "danger")
            return redirect(url_for("modifier_profil"))

        # Gestion photo de profil
        utilisateur = execute_secure(
            "SELECT * FROM utilisateurs WHERE id = ?",
            params=(utilisateur_id,),
            fetchone=True
        )
        photo = utilisateur["photo_profil"]

        if "photo_profil" in request.files:
            fichier = request.files["photo_profil"]
            if fichier and fichier.filename != "" \
                    and allowed_file(fichier.filename):
                nom_fichier = secure_filename(fichier.filename)
                fichier.save(os.path.join(
                    app.config["UPLOAD_FOLDER"], nom_fichier))
                photo = nom_fichier

        # CONTRE-MESURE PRINCIPALE contre la Second-Order :
        # On utilise l'ID (entier contrôlé par le serveur)
        # et jamais le pseudo dans le WHERE — le pseudo malveillant
        # tsahui'-- ne peut donc jamais s'injecter dans cette requête
        execute_secure(
            """UPDATE utilisateurs
               SET bio = ?, email = ?, photo_profil = ?
               WHERE id = ?""",
            params=(bio, email, photo, utilisateur_id),
            commit=True
        )

        flash("Profil mis à jour avec succès.", "success")
        return redirect(url_for(
            "profil",
            pseudo=utilisateur["pseudo"]
        ))

    utilisateur = execute_secure(
        "SELECT * FROM utilisateurs WHERE id = ?",
        params=(utilisateur_id,),
        fetchone=True
    )
    return render_template("modifier_profil.html", utilisateur=utilisateur)


# ============================================================
# ROUTES DE MESSAGERIE
# ============================================================

@app.route("/messages")
@login_required
def messages():
    """SÉCURISÉ : Requête paramétrée sur l'identifiant utilisateur."""
    utilisateur_id = session["utilisateur_id"]

    conversations = execute_secure(
        """SELECT
               mp.*,
               u.pseudo as interlocuteur_pseudo,
               u.photo_profil as interlocuteur_photo,
               u.id as interlocuteur_id
           FROM messages_prives mp
           JOIN utilisateurs u ON (
               CASE
                   WHEN mp.expediteur_id = ?
                   THEN u.id = mp.destinataire_id
                   ELSE u.id = mp.expediteur_id
               END
           )
           WHERE mp.expediteur_id = ?
              OR mp.destinataire_id = ?
           GROUP BY
               CASE
                   WHEN mp.expediteur_id = ?
                   THEN mp.destinataire_id
                   ELSE mp.expediteur_id
               END
           ORDER BY mp.date_envoi DESC""",
        params=(utilisateur_id, utilisateur_id,
                utilisateur_id, utilisateur_id),
        fetchall=True
    )

    return render_template("messages.html", conversations=conversations)


@app.route("/conversation/<int:interlocuteur_id>")
@login_required
def conversation(interlocuteur_id):
    """SÉCURISÉ : Paramètres liés + typage int par Flask."""
    utilisateur_id = session["utilisateur_id"]

    interlocuteur = execute_secure(
        "SELECT * FROM utilisateurs WHERE id = ?",
        params=(interlocuteur_id,),
        fetchone=True
    )

    if not interlocuteur:
        flash("Utilisateur introuvable.", "danger")
        return redirect(url_for("messages"))

    msgs = execute_secure(
        """SELECT mp.*, u.pseudo, u.photo_profil
           FROM messages_prives mp
           JOIN utilisateurs u ON u.id = mp.expediteur_id
           WHERE (mp.expediteur_id = ? AND mp.destinataire_id = ?)
              OR (mp.expediteur_id = ? AND mp.destinataire_id = ?)
           ORDER BY mp.date_envoi ASC""",
        params=(utilisateur_id, interlocuteur_id,
                interlocuteur_id, utilisateur_id),
        fetchall=True
    )

    return render_template(
        "conversation.html",
        interlocuteur=interlocuteur,
        msgs=msgs
    )


@app.route("/envoyer-message/<int:destinataire_id>", methods=["POST"])
@login_required
def envoyer_message(destinataire_id):
    """Envoie un message privé — requête paramétrée."""
    contenu = request.form.get("contenu", "").strip()

    if not contenu:
        return redirect(url_for(
            "conversation", interlocuteur_id=destinataire_id
        ))

    if not valider_longueur(contenu, 1000):
        flash("Message trop long.", "danger")
        return redirect(url_for(
            "conversation", interlocuteur_id=destinataire_id
        ))

    maintenant = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    execute_secure(
        """INSERT INTO messages_prives
           (contenu, date_envoi, expediteur_id, destinataire_id)
           VALUES (?, ?, ?, ?)""",
        params=(contenu, maintenant,
                session["utilisateur_id"], destinataire_id),
        commit=True
    )

    return redirect(url_for(
        "conversation", interlocuteur_id=destinataire_id
    ))


# ============================================================
# LANCEMENT DE L'APPLICATION
# ============================================================

if __name__ == "__main__":
    app.run(debug=True, port=5001)