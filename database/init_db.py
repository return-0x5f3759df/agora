import sqlite3
import os
from werkzeug.security import generate_password_hash
from datetime import datetime

# Chemin vers la base de données
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "agora.db")

def init_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Activation des clés étrangères
    cursor.execute("PRAGMA foreign_keys = ON")

    # ============================================================
    # CRÉATION DES TABLES
    # ============================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS utilisateurs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pseudo TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            mot_de_passe TEXT NOT NULL,
            bio TEXT DEFAULT '',
            photo_profil TEXT DEFAULT 'default.png',
            date_inscription TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS publications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contenu TEXT NOT NULL,
            date_publication TEXT NOT NULL,
            utilisateur_id INTEGER NOT NULL,
            FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS commentaires (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contenu TEXT NOT NULL,
            date_commentaire TEXT NOT NULL,
            utilisateur_id INTEGER NOT NULL,
            publication_id INTEGER NOT NULL,
            FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs(id),
            FOREIGN KEY (publication_id) REFERENCES publications(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL UNIQUE,
            utilisateur_id INTEGER NOT NULL,
            date_expiration TEXT NOT NULL,
            FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages_prives (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contenu TEXT NOT NULL,
            date_envoi TEXT NOT NULL,
            expediteur_id INTEGER NOT NULL,
            destinataire_id INTEGER NOT NULL,
            FOREIGN KEY (expediteur_id) REFERENCES utilisateurs(id),
            FOREIGN KEY (destinataire_id) REFERENCES utilisateurs(id)
        )
    """)

    # ============================================================
    # INSERTION DES DONNÉES DE TEST
    # ============================================================

    maintenant = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    utilisateurs = [
        ("tsahui",  "tsahui@agora.cm",  generate_password_hash("password123"), "Étudiant en informatique à l'UY1. Passionné de cybersécurité 🔐", maintenant),
        ("ningahe", "ningahe@agora.cm", generate_password_hash("password123"), "Développeur passionné. Co-auteur du projet Agora 💻", maintenant),
        ("marie_a", "marie@agora.cm",   generate_password_hash("password123"), "Étudiante en réseaux et sécurité. Fan de CTF 🚩", maintenant),
        ("paulk",   "paul@agora.cm",    generate_password_hash("password123"), "La sécurité commence par une bonne conception 🛡️", maintenant),
    ]

    cursor.executemany("""
        INSERT OR IGNORE INTO utilisateurs (pseudo, email, mot_de_passe, bio, date_inscription)
        VALUES (?, ?, ?, ?, ?)
    """, utilisateurs)

    publications = [
        ("Les injections SQL sont encore parmi les vulnérabilités les plus exploitées. Un projet de démonstration s'impose ! 🔐", maintenant, 1),
        ("Première semaine de conception du projet INF4258 — les bases de données n'ont plus de secrets pour nous 💪", maintenant, 1),
        ("Quelqu'un a testé Flask avec SQLite pour un projet de sécu ? C'est vraiment léger et efficace comme stack.", maintenant, 3),
        ("La sécurité informatique commence par une bonne conception. Ne codez jamais sans avoir modélisé votre BDD au préalable.", maintenant, 4),
        ("Projet Agora en cours de développement — deux versions, une vulnérable, une sécurisée. La démonstration va être 🔥", maintenant, 2),
    ]

    cursor.executemany("""
        INSERT OR IGNORE INTO publications (contenu, date_publication, utilisateur_id)
        VALUES (?, ?, ?)
    """, publications)

    commentaires = [
        ("Totalement d'accord ! La blind injection time-based est particulièrement insidieuse.", maintenant, 2, 1),
        ("Les requêtes paramétrées règlent 90% des problèmes. Le reste c'est la validation d'entrées.", maintenant, 4, 1),
        ("Flask + SQLite c'est la combinaison parfaite pour ce type de projet 👌", maintenant, 2, 3),
        ("Belle initiative ! Hâte de voir la démonstration en soutenance.", maintenant, 3, 5),
    ]

    cursor.executemany("""
        INSERT OR IGNORE INTO commentaires (contenu, date_commentaire, utilisateur_id, publication_id)
        VALUES (?, ?, ?, ?)
    """, commentaires)

    messages_prives = [
        ("Salut ! Tu as avancé sur les maquettes du projet ?", maintenant, 2, 1),
        ("Oui ! Presque toutes terminées. La page de recherche montre bien l'injection UNION 💪", maintenant, 1, 2),
        ("Parfait. Et la second-order sur la modification du profil, c'est bien pensé aussi 🔐", maintenant, 2, 1),
        ("Exactement ! Plus qu'à passer au développement maintenant 🚀", maintenant, 1, 2),
    ]

    cursor.executemany("""
        INSERT OR IGNORE INTO messages_prives (contenu, date_envoi, expediteur_id, destinataire_id)
        VALUES (?, ?, ?, ?)
    """, messages_prives)

    conn.commit()
    conn.close()
    print("✅ Base de données créée et peuplée avec succès.")
    print(f"📁 Fichier : {DB_PATH}")

if __name__ == "__main__":
    init_database()