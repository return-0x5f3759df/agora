import sqlite3
import os
import secrets
from datetime import datetime, timedelta
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
app.secret_key = "agora_vulnerable_secret_key_2026"

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
    """Retourne une connexion à la base de données pour la requête en cours."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    """Ferme la connexion à la base de données en fin de requête."""
    db = g.pop("db", None)
    if db is not None:
        db.close()

def allowed_file(filename):
    """Vérifie que l'extension du fichier est autorisée."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ============================================================
# ZONE DE TRAÇABILITÉ SQL
# ============================================================

sql_trace = []

def execute_vulnerable(query, params=(), fetchone=False, fetchall=False, commit=False):
    """
    Exécute une requête SQL vulnérable (concaténation directe).
    Enregistre la requête dans sql_trace pour l'affichage en temps réel.
    """
    db = get_db()
    
    # On enregistre la requête brute telle qu'elle sera exécutée
    sql_trace.append(f"[VULNÉRABLE] {query}")
    
    try:
        cursor = db.execute(query)
        if commit:
            db.commit()
            return None
        if fetchone:
            return cursor.fetchone()
        if fetchall:
            return cursor.fetchall()
    except sqlite3.Error as e:
        # VULNÉRABILITÉ INTENTIONNELLE : l'erreur SQL complète est
        # enregistrée dans la trace ET stockée dans la session Flask
        # pour être affichée à l'utilisateur — exactement ce qu'un
        # développeur négligent ferait en production
        erreur = f"ERREUR SQL : {str(e)}"
        sql_trace.append(erreur)
        from flask import session
        session['sql_error'] = erreur
        return None

def execute_safe(query, params=(), fetchone=False, fetchall=False, commit=False):
    """
    Exécute une requête SQL sécurisée (requêtes paramétrées).
    Utilisée uniquement pour les opérations qui doivent rester
    sécurisées même dans la version vulnérable (ex: insertion de session).
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
        sql_trace.append(f"ERREUR SQL : {str(e)}")
        return None

# ============================================================
# DÉCORATEUR DE PROTECTION DES ROUTES
# ============================================================

def login_required(f):
    """
    Décorateur qui redirige vers la connexion si l'utilisateur
    n'est pas authentifié.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "utilisateur_id" not in session:
            flash("Vous devez être connecté pour accéder à cette page.", "warning")
            return redirect(url_for("connexion"))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================
# VARIABLE DE CONTEXTE GLOBAL
# ============================================================

@app.context_processor
def inject_globals():
    """
    Injecte des variables disponibles dans tous les templates :
    - current_user : l'utilisateur connecté
    - sql_trace : la dernière requête SQL exécutée
    """
    current_user = None
    if "utilisateur_id" in session:
        current_user = execute_safe(
            "SELECT * FROM utilisateurs WHERE id = ?",
            params=(session["utilisateur_id"],),
            fetchone=True
        )
    return {
        "current_user": current_user,
        "sql_trace": sql_trace
    }

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
    VULNÉRABILITÉ : Injection classique (Error-based) et contournement
    La condition AND mot_de_passe != '' peut être commentée avec --
    ce qui supprime toute vérification de mot de passe au niveau SQL.
    """
    if request.method == "POST":
        email = request.form.get("email", "")
        mot_de_passe = request.form.get("mot_de_passe", "")

        # ⚠️ REQUÊTE VULNÉRABLE — email concaténé directement
        query = f"""
            SELECT * FROM utilisateurs
            WHERE email = '{email}'
            AND mot_de_passe != ''
        """
        utilisateur = execute_vulnerable(query, fetchone=True)

        if utilisateur:
            # Vérification du mot de passe en Python
            # Cette vérification est contournée quand -- commente
            # la clause AND mot_de_passe != '' dans la requête SQL
            # car dans ce cas utilisateur est retourné sans vérification
            if check_password_hash(utilisateur["mot_de_passe"], mot_de_passe):
                session.clear()
                session["utilisateur_id"] = utilisateur["id"]
                session["pseudo"] = utilisateur["pseudo"]
                flash("Connexion réussie. Bienvenue sur Agora !", "success")
                return redirect(url_for("fil"))
            else:
                # Si -- est injecté, mot_de_passe est vide ou faux
                # mais utilisateur est retourné quand même par la requête
                # On contourne cette vérification en acceptant si
                # la requête a retourné un utilisateur via injection
                if not mot_de_passe or "'" in email or "--" in email:
                    session.clear()
                    session["utilisateur_id"] = utilisateur["id"]
                    session["pseudo"] = utilisateur["pseudo"]
                    flash("Connexion réussie. Bienvenue sur Agora !", "success")
                    return redirect(url_for("fil"))
                flash("Identifiants incorrects. Réessayez.", "danger")
        else:
            flash("Identifiants incorrects. Réessayez.", "danger")

    return render_template("connexion.html")

@app.route("/inscription", methods=["GET", "POST"])
def inscription():
    """
    VULNÉRABILITÉ : Injection Second-Order (étape 1)
    Le pseudo est stocké en base sans traitement particulier.
    La faille s'activera lors de la modification du profil.
    """
    if request.method == "POST":
        pseudo = request.form.get("pseudo", "")
        email = request.form.get("email", "")
        mot_de_passe = request.form.get("mot_de_passe", "")

        if not pseudo or not email or not mot_de_passe:
            flash("Tous les champs sont obligatoires.", "danger")
            return render_template("inscription.html")

        # Vérification si le pseudo ou l'email existe déjà
        existant = execute_safe(
            "SELECT id FROM utilisateurs WHERE email = ? OR pseudo = ?",
            params=(email, pseudo),
            fetchone=True
        )
        if existant:
            flash("Cet email ou ce pseudo est déjà utilisé.", "danger")
            return render_template("inscription.html")

        # Gestion de la photo de profil
        photo = "default.png"
        if "photo_profil" in request.files:
            fichier = request.files["photo_profil"]
            if fichier and fichier.filename != "" and allowed_file(fichier.filename):
                nom_fichier = secure_filename(fichier.filename)
                fichier.save(os.path.join(app.config["UPLOAD_FOLDER"], nom_fichier))
                photo = nom_fichier

        # Hash du mot de passe
        mot_de_passe_hash = generate_password_hash(mot_de_passe)
        maintenant = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ⚠️ SECOND-ORDER ÉTAPE 1 : le pseudo malveillant est stocké ici
        # Il sera relu et injecté plus tard dans une requête UPDATE
        execute_safe(
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
    VULNÉRABILITÉ : Injection Blind Time-based
    Le paramètre 'tri' passé dans l'URL est injecté directement
    dans la clause ORDER BY sans validation.
    """
    tri = request.args.get("tri", "date_publication")

    # ⚠️ REQUÊTE VULNÉRABLE — le paramètre tri est injecté dans ORDER BY
    query = f"""
        SELECT p.*, u.pseudo, u.photo_profil
        FROM publications p
        JOIN utilisateurs u ON u.id = p.utilisateur_id
        ORDER BY p.{tri} DESC
        LIMIT 20
    """
    publications = execute_vulnerable(query, fetchall=True)

    return render_template("fil.html", publications=publications)


@app.route("/publication/<int:pub_id>")
@login_required
def publication(pub_id):
    """
    Affiche une publication et ses commentaires.
    VULNÉRABILITÉ : Injection Blind Boolean-based sur pub_id.
    """
    # ⚠️ REQUÊTE VULNÉRABLE — pub_id concaténé directement
    query = f"SELECT p.*, u.pseudo, u.photo_profil FROM publications p JOIN utilisateurs u ON u.id = p.utilisateur_id WHERE p.id = {pub_id}"
    pub = execute_vulnerable(query, fetchone=True)

    if not pub:
        flash("Publication introuvable.", "danger")
        return redirect(url_for("fil"))

    # Récupération des commentaires
    query_com = f"""
        SELECT c.*, u.pseudo, u.photo_profil
        FROM commentaires c
        JOIN utilisateurs u ON u.id = c.utilisateur_id
        WHERE c.publication_id = {pub_id}
        ORDER BY c.date_commentaire ASC
    """
    commentaires = execute_vulnerable(query_com, fetchall=True)

    return render_template("publication.html", pub=pub, commentaires=commentaires)


@app.route("/commenter/<int:pub_id>", methods=["POST"])
@login_required
def commenter(pub_id):
    """Ajoute un commentaire à une publication."""
    contenu = request.form.get("contenu", "").strip()

    if not contenu:
        flash("Le commentaire ne peut pas être vide.", "danger")
        return redirect(url_for("publication", pub_id=pub_id))

    maintenant = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    execute_safe(
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
    """Publie un nouveau message sur le fil d'actualité."""
    contenu = request.form.get("contenu", "").strip()

    if not contenu:
        flash("La publication ne peut pas être vide.", "danger")
        return redirect(url_for("fil"))

    if len(contenu) > 280:
        flash("La publication ne peut pas dépasser 280 caractères.", "danger")
        return redirect(url_for("fil"))

    maintenant = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    execute_safe(
        """INSERT INTO publications (contenu, date_publication, utilisateur_id)
           VALUES (?, ?, ?)""",
        params=(contenu, maintenant, session["utilisateur_id"]),
        commit=True
    )

    return redirect(url_for("fil"))


@app.route("/recherche")
@login_required
def recherche():
    """
    VULNÉRABILITÉ : Injection UNION-based
    Le paramètre 'q' est injecté directement dans la requête LIKE
    sans aucun traitement — vecteur idéal pour une attaque UNION.
    """
    q = request.args.get("q", "")
    resultats = []

    if q:
        # ⚠️ REQUÊTE VULNÉRABLE — q injecté directement dans LIKE
        query = f"""
            SELECT id, pseudo, bio, email, photo_profil
            FROM utilisateurs
            WHERE pseudo LIKE '%{q}%'
        """
        resultats = execute_vulnerable(query, fetchall=True)

    return render_template("recherche.html", resultats=resultats, q=q)

# ============================================================
# ROUTES DE PROFIL
# ============================================================

@app.route("/profil/<pseudo>")
@login_required
def profil(pseudo):
    """
    Affiche le profil d'un utilisateur.
    VULNÉRABILITÉ : Injection Blind Boolean-based sur le pseudo.
    """
    # ⚠️ REQUÊTE VULNÉRABLE — pseudo concaténé directement
    query = f"SELECT * FROM utilisateurs WHERE pseudo = '{pseudo}'"
    utilisateur = execute_vulnerable(query, fetchone=True)

    if not utilisateur:
        flash("Utilisateur introuvable.", "danger")
        return redirect(url_for("fil"))

    query_pubs = f"""
        SELECT * FROM publications
        WHERE utilisateur_id = {utilisateur['id']}
        ORDER BY date_publication DESC
    """
    publications = execute_vulnerable(query_pubs, fetchall=True)

    query_stats = f"""
        SELECT COUNT(*) as total FROM commentaires
        WHERE utilisateur_id = {utilisateur['id']}
    """
    stats = execute_vulnerable(query_stats, fetchone=True)

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
    VULNÉRABILITÉ : Injection Second-Order (étape 2)
    Le pseudo est récupéré depuis la base de données puis injecté
    directement dans une requête UPDATE sans traitement.
    C'est ici que la bombe posée à l'inscription explose.
    """
    utilisateur_id = session["utilisateur_id"]

    if request.method == "POST":
        bio = request.form.get("bio", "").strip()
        email = request.form.get("email", "").strip()

        # Récupération du pseudo depuis la base — on lui fait confiance à tort
        utilisateur = execute_safe(
            "SELECT * FROM utilisateurs WHERE id = ?",
            params=(utilisateur_id,),
            fetchone=True
        )
        pseudo_actuel = utilisateur["pseudo"]

        # Gestion de la photo de profil
        photo = utilisateur["photo_profil"]
        if "photo_profil" in request.files:
            fichier = request.files["photo_profil"]
            if fichier and fichier.filename != "" and allowed_file(fichier.filename):
                nom_fichier = secure_filename(fichier.filename)
                fichier.save(os.path.join(app.config["UPLOAD_FOLDER"], nom_fichier))
                photo = nom_fichier

        # ⚠️ SECOND-ORDER ÉTAPE 2 : le pseudo récupéré de la base
        # est injecté directement dans la requête UPDATE.
        # Si le pseudo contient admin'-- alors la requête devient :
        # UPDATE utilisateurs SET bio='...', email='...',
        # photo_profil='...' WHERE pseudo='admin'--'
        # ce qui met à jour le compte admin au lieu du compte actuel.
        query = f"""
            UPDATE utilisateurs
            SET bio='{bio}', email='{email}', photo_profil='{photo}'
            WHERE pseudo='{pseudo_actuel}'
        """
        execute_vulnerable(query, commit=True)

        flash("Profil mis à jour avec succès.", "success")
        return redirect(url_for("profil", pseudo=pseudo_actuel))

    utilisateur = execute_safe(
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
    """
    Affiche la liste des conversations de l'utilisateur connecté.
    VULNÉRABILITÉ : Injection Blind sur l'identifiant utilisateur.
    """
    utilisateur_id = session["utilisateur_id"]

    # ⚠️ REQUÊTE VULNÉRABLE
    query = f"""
        SELECT
            mp.*,
            u.pseudo as interlocuteur_pseudo,
            u.photo_profil as interlocuteur_photo,
            u.id as interlocuteur_id
        FROM messages_prives mp
        JOIN utilisateurs u ON (
            CASE
                WHEN mp.expediteur_id = {utilisateur_id}
                THEN u.id = mp.destinataire_id
                ELSE u.id = mp.expediteur_id
            END
        )
        WHERE mp.expediteur_id = {utilisateur_id}
           OR mp.destinataire_id = {utilisateur_id}
        GROUP BY
            CASE
                WHEN mp.expediteur_id = {utilisateur_id}
                THEN mp.destinataire_id
                ELSE mp.expediteur_id
            END
        ORDER BY mp.date_envoi DESC
    """
    conversations = execute_vulnerable(query, fetchall=True)

    return render_template("messages.html", conversations=conversations)


@app.route("/conversation/<int:interlocuteur_id>")
@login_required
def conversation(interlocuteur_id):
    """
    Affiche la conversation entre l'utilisateur connecté
    et un interlocuteur donné.
    """
    utilisateur_id = session["utilisateur_id"]

    # Récupération de l'interlocuteur
    interlocuteur = execute_safe(
        "SELECT * FROM utilisateurs WHERE id = ?",
        params=(interlocuteur_id,),
        fetchone=True
    )

    if not interlocuteur:
        flash("Utilisateur introuvable.", "danger")
        return redirect(url_for("messages"))

    # ⚠️ REQUÊTE VULNÉRABLE
    query = f"""
        SELECT mp.*, u.pseudo, u.photo_profil
        FROM messages_prives mp
        JOIN utilisateurs u ON u.id = mp.expediteur_id
        WHERE (mp.expediteur_id = {utilisateur_id}
           AND mp.destinataire_id = {interlocuteur_id})
           OR (mp.expediteur_id = {interlocuteur_id}
           AND mp.destinataire_id = {utilisateur_id})
        ORDER BY mp.date_envoi ASC
    """
    msgs = execute_vulnerable(query, fetchall=True)

    return render_template(
        "conversation.html",
        interlocuteur=interlocuteur,
        msgs=msgs
    )


@app.route("/envoyer-message/<int:destinataire_id>", methods=["POST"])
@login_required
def envoyer_message(destinataire_id):
    """Envoie un message privé à un utilisateur."""
    contenu = request.form.get("contenu", "").strip()

    if not contenu:
        return redirect(url_for("conversation",
                                interlocuteur_id=destinataire_id))

    maintenant = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    execute_safe(
        """INSERT INTO messages_prives
           (contenu, date_envoi, expediteur_id, destinataire_id)
           VALUES (?, ?, ?, ?)""",
        params=(contenu, maintenant,
                session["utilisateur_id"], destinataire_id),
        commit=True
    )

    return redirect(url_for("conversation",
                            interlocuteur_id=destinataire_id))

@app.route("/vider-trace")
def vider_trace():
    """Vide la zone de traçabilité SQL."""
    sql_trace.clear()
    return redirect(request.referrer or url_for("fil"))

# ============================================================
# LANCEMENT DE L'APPLICATION
# ============================================================

if __name__ == "__main__":
    app.run(debug=True, port=5000)