# Livrable 2 : version intermédiaire (VULNERABLE)
Application Flask de partage de fichiers : authentification, dépôt, chiffrement AES-256-GCM, empreinte SHA-256, signature ECDSA, certificats X.509 d'une AC locale, journal d'audit.
Cette version contient des failles volontaires, à exploiter en local  puis à corriger . 

## Étapes pour créer et lancer le projet
1. Installer les outils : Python, Git, OpenSSL (`python --version`, `git --version`, `openssl version`).
2. Créer le dossier et le dépôt Git : `mkdir securefiles && cd securefiles && git init && git checkout -b vulnerable`.
3. Créer l'arborescence : `app/ app/templates/ security/ pki/ tests/ data/ storage/`, puis un fichier vide `security/__init__.py`.
4. Créer l'environnement virtuel : `python -m venv venv`, puis `.\venv\Scripts\Activate.ps1`.
5. Installer les dépendances : copier `requirements.txt` puis `pip install -r requirements.txt`.
6. Ajouter les fichiers dans cet ordre (chaque fichier est détaillé plus bas) : `config.py`, `.gitignore`, `security/*.py`, `app/db.py`, `app/__init__.py`, `app/routes.py`, `app/templates/*.html`, `run.py`.
7. Lancer l'application : `python run.py`, puis ouvrir http://127.0.0.1:5000. La base SQLite et l'AC locale (`pki/ca.key`, `pki/ca.crt`) sont créées automatiquement.
8. Tester le scénario Alice / Bob : s'inscrire en `alice` et `bob` (un certificat est émis à chaque inscription), se connecter en Alice, déposer un PDF, le partager avec `bob`, se connecter en Bob, cliquer « Vérifier » : intégrité, certificat et signature sont affichés.
9. Lancer les tests automatiques : `python -m pytest -v` (tests : modules crypto, scénarios Alice/Bob, preuves d'attaques).
10. Démontrer la PKI avec OpenSSL : `bash pki/openssl_demo.sh` (certificat valide, expiré, AC inconnue).
11. Valider et rendre : `git add . && git commit -m "V1 vulnérable fonctionnelle"`.

## Fonctionnalités du livrable 2
|--------------------------------------------------------------------------|----------------------------------------------------------|
| Exigence                                                                 | Où dans le code                                          | 
|--------------------------------------------------------------------------|----------------------------------------------------------|
| Inscription, connexion, sessions                                         | `app/routes.py` (`register`, `login`, `logout`)          | 
| Dépôt, partage, révocation, téléchargement                               | `app/routes.py`(`upload`, `share`, `unshare`, `download`)| 
| AES-256-GCM, clé par fichier, nonce 96 bits, AAD, clé enveloppée         | `security/crypto.py`                                     | 
| Empreinte SHA-256 à chaque dépôt, vérification à chaque téléchargement   | `security/hashing.py`, `app/routes.py`(`open_and_verify`)|
| Signature ECDSA P-256 sur `v1|id|empreinte`                              | `security/signature.py`                                  | 
| AC locale, certificats, rejet expiré / AC inconnue / mauvais utilisateur | `security/certs.py`, `pki/openssl_demo.sh`               | 
| Comparaison avec un fichier local                                        | `app/routes.py`(`verify_local`)                          | 
| Journal d'audit                                                          | `app/routes.py`(`log()`, route `/audit`)                 | 
|--------------------------------------------------------------------------|----------------------------------------------------------|

## Vulnérabilités volontaires 
| # | Vulnérabilité                                             | Catégorie OWASP            | Où                    | Comment la reproduire                                                          |
|---|-----------------------------------------------------------|----------------------------|-----------------------|--------------------------------------------------------------------------------|
| V1 | Injection SQL (connexion)                                | A03 Injection              | `login`               | identifiant `alice' --`, mot de passe quelconque                               |
| V2 | Injection SQL (recherche, fuite des hachages)            | A03 Injection              | `search`              | `zzz%' UNION SELECT id, username \|\| ':' \|\| password_hash, 0 FROM users --` |
| V3 | XSS réfléchi                                             | A03 Injection              | `search.html`         | `<script>alert(1)</script>` dans la recherche                                  |
| V4 | XSS stocké                                               | A03 Injection              | `files.html`          | déposer un fichier nommé `<img src=x onerror=alert(1)>.pdf`                    |
| V5 | IDOR (lecture du fichier d'autrui)                       | A01 Contrôle d'accès       | `get_file`            | connecté en autre utilisateur, ouvrir `/download/1`                            |
| V6 | Partage sans contrôle de propriété + CSRF                | A01 / A04                  | `share`               | POST `/share/1` depuis une page externe ou un autre compte                     |
| V7 | Pas de limite de tentatives, messages différents         | A07 Authentification       | `login`               | script de 20 essais ; « Utilisateur inconnu » vs « Mot de passe incorrect »    |
| V8 | Mots de passe MD5 sans sel                               | A02 Défaillances crypto    | `hashing.py`          | lire `users.password_hash`                                                     |
| V9 | Clé maître et clé Flask codées en dur                    | A02                        | `config.py`           | lire le code source                                                            |
| V10 | Clés privées en clair (base et clé de l'AC)             | A02                        | `db.py`, `certs.py`   | ouvrir `data/app.db` et `pki/ca.key`                                           |
| V11 | Téléversement non contrôlé, chemin `../`                | A04 / A05                  | `upload`              | nom de fichier `../../x`, très gros fichier, double extension                  |
| V12 | Cookie sans HttpOnly, session non régénérée             | A07                        | `__init__.py`, `login`| `document.cookie` dans la console                                              |
| V13 | Journal public, `debug=True`                            | A05 Mauvaise configuration | `audit`, `run.py`     | ouvrir `/audit` sans compte ; provoquer une erreur                             |
|-----|---------------------------------------------------------|----------------------------|-----------------------|--------------------------------------------------------------------------------|
Les tests `tests/test_attacks_v1.py` servent de preuves automatiques : ils passent quand l'attaque réussit. En version final on inverse les assertions pour prouver que l'attaque échoue.