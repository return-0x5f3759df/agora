# AGORA — Démonstration de vulnérabilités SQL Injection et contre-mesures

## 📋 Présentation

Ce projet est une application web de type mini-réseau social développée dans le cadre de
l'unité d'enseignement INF4258 (Master 1 Cybersécurité, Université de Yaoundé 1). Il vise à
illustrer concrètement les mécanismes d'attaque par injection SQL (SQL Injection) ainsi que
les contre-mesures permettant de les neutraliser.

L'application est déclinée en **deux versions visuellement identiques** :
- 🔴 Une version **intentionnellement vulnérable**
- 🟢 Une version **sécurisée**

## 🎯 Objectifs

- Comprendre et démontrer les 5 grandes familles d'injections SQL : Error-based (classique),
  UNION-based, Blind Boolean-based, Blind Time-based et Second-Order
- Concevoir deux versions comparables d'une même application (vulnérable / sécurisée)
- Illustrer de façon pratique l'efficacité des contre-mesures mises en place
- Documenter l'ensemble de la démarche, des choix de conception aux résultats observés

## 🛠️ Stack technique

| Composant       | Technologie     |
|-----------------|-----------------|
| Langage         | Python          |
| Framework       | Flask           |
| Base de données | SQLite          |
| Frontend        | Tailwind CSS    |
| Environnement   | VS Code         |

## 🚀 Installation

```bash
git clone https://github.com/return-0x5f3759df/agora.git
cd agora
python -m venv venv
source venv/bin/activate      # Windows : venv\Scripts\activate
pip install -r requirements.txt
python app.py
ou depuis VS Code après le téléchargement du dossier
1. Arrêter Flask : Ctrl+C dans le terminal
2. Recréer la base : python database/init_db.py
3. Vider les cookies Chrome : F12 → Application → Cookies → Supprimer session
4. Relancer Flask : python vulnerable/app.py
5. Se connecter : tsahui@agora.cm / password123
## 📸 Aperçu: 

<img width="1119" height="764" alt="aagora_3" src="https://github.com/user-attachments/assets/7240fb02-c151-4b42-9160-fd9d4883d6f8" />
<img width="1081" height="571" alt="aagora_2" src="https://github.com/user-attachments/assets/3831b81d-55a0-42bb-ad91-354edab0e278" />
<img width="1066" height="573" alt="aagora_1" src="https://github.com/user-attachments/assets/385673d3-b30c-4e69-87ef-0a4a34ceac61" />

## 👤 Auteur

**Tsahui Nembot Christ Socrate** — Master Cybersécurité, Université de Yaoundé 1
Projet — INF4258, 2025/2026
