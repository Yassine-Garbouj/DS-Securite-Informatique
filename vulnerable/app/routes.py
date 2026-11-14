"""Routes de la version vulnérable (volontairement vulnérable).
Les failles sont repérées par le commentaire « VULNERABILITE »."""
import datetime
import io
import os
import sqlite3
from functools import wraps

from cryptography.exceptions import InvalidTag
from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, send_file, session, url_for)

from security import certs, crypto, hashing, signature
from .db import get_db

bp = Blueprint("main", __name__)


# ---------- utilitaires ----------
def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def log(action, file_id=None, result=""):
    db = get_db()
    db.execute("INSERT INTO audit_log(ts, username, action, file_id, result) "
               "VALUES (?, ?, ?, ?, ?)",
               (now(), session.get("username", "anonyme"), action, file_id, result))
    db.commit()


def current_user():
    if "user_id" not in session:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?",
                            (session["user_id"],)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("main.login"))
        return view(*args, **kwargs)
    return wrapper


# ---------- authentification ----------
@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form.get("email", "")
        password = request.form["password"]
        # VULNERABILITE : aucune politique de mot de passe, MD5 sans sel
        pw_hash = hashing.weak_password_hash(password)
        ca_key, ca_cert = certs.load_or_create_ca(current_app.config["PKI_DIR"])
        key_pem, cert_pem = certs.issue_user_cert(username, ca_key, ca_cert)
        db = get_db()
        try:
            db.execute("INSERT INTO users(username, email, password_hash, cert_pem, key_pem) "
                       "VALUES (?, ?, ?, ?, ?)", (username, email, pw_hash, cert_pem, key_pem))
            db.commit()
        except sqlite3.IntegrityError:
            flash("Ce nom d'utilisateur existe déjà")
            return render_template("register.html")
        log("inscription")
        flash("Compte créé, un certificat a été émis. Connectez-vous.")
        return redirect(url_for("main.login"))
    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        # VULNERABILITE : injection SQL (requête construite par concaténation)
        query = ("SELECT * FROM users WHERE username = '" + username +
                 "' AND password_hash = '" + hashing.weak_password_hash(password) + "'")
        try:
            user = db.execute(query).fetchone()
        except Exception as exc:
            # VULNERABILITE : message d'erreur SQL affiché à l'utilisateur
            flash("Erreur SQL : %s" % exc)
            return render_template("login.html")
        if user:
            # VULNERABILITE : pas de régénération de session, pas de limite de tentatives
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            log("connexion_ok")
            return redirect(url_for("main.files"))
        exists = db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        # VULNERABILITE : messages différents (énumération des comptes)
        flash("Mot de passe incorrect" if exists else "Utilisateur inconnu")
        log("connexion_echec")
    return render_template("login.html")


@bp.route("/logout")
def logout():
    log("deconnexion")
    session.clear()  # VULNERABILITE : cookie signé toujours rejouable (session côté client)
    return redirect(url_for("main.index"))


# ---------- fichiers ----------
@bp.route("/files")
@login_required
def files():
    db = get_db()
    uid = session["user_id"]
    own = db.execute("SELECT * FROM files WHERE owner_id = ? ORDER BY id DESC", (uid,)).fetchall()
    shared = db.execute(
        "SELECT f.*, u.username AS owner FROM files f "
        "JOIN shares s ON s.file_id = f.id JOIN users u ON u.id = f.owner_id "
        "WHERE s.recipient_id = ? ORDER BY f.id DESC", (uid,)).fetchall()
    return render_template("files.html", own=own, shared=shared)


@bp.route("/upload", methods=["POST"])
@login_required
def upload():
    user = current_user()
    uploaded = request.files["file"]
    # VULNERABILITE : nom, extension, type MIME et taille jamais contrôlés
    name = uploaded.filename
    data = uploaded.read()
    sha = hashing.sha256_hex(data)
    db = get_db()
    cur = db.execute(
        "INSERT INTO files(owner_id, original_name, stored_name, size, sha256, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)", (user["id"], name, name + ".enc", len(data), sha, now()))
    file_id = cur.lastrowid
    aad = ("%d|%d" % (file_id, user["id"])).encode()
    ciphertext, nonce, wrapped = crypto.encrypt_file(data, aad, current_app.config["MASTER_KEY"])
    # VULNERABILITE : le nom fourni par l'utilisateur sert de chemin (« ../ », écrasement)
    path = os.path.join(current_app.config["STORAGE_DIR"], name + ".enc")
    with open(path, "wb") as fh:
        fh.write(ciphertext)
    sig = signature.sign(user["key_pem"], signature.message_for(file_id, sha))
    db.execute("UPDATE files SET nonce = ?, wrapped_key = ?, signature = ? WHERE id = ?",
               (nonce, wrapped, sig, file_id))
    db.commit()
    log("depot", file_id, "chiffré AES-GCM, empreinte et signature enregistrées")
    flash("Fichier déposé, chiffré et signé")
    return redirect(url_for("main.files"))


def open_and_verify(f):
    """Déchiffre le fichier puis vérifie : tag GCM, empreinte SHA-256, certificat, signature."""
    report = {"data": None, "integrity_ok": False, "integrity_msg": "",
              "cert_ok": False, "cert_msg": "", "sig_ok": False, "sig_msg": ""}
    path = os.path.join(current_app.config["STORAGE_DIR"], f["stored_name"])
    try:
        with open(path, "rb") as fh:
            ciphertext = fh.read()
    except OSError:
        report["integrity_msg"] = "Échec de vérification : fichier chiffré introuvable"
        return report
    aad = ("%d|%d" % (f["id"], f["owner_id"])).encode()
    try:
        data = crypto.decrypt_file(ciphertext, f["nonce"], f["wrapped_key"], aad,
                                   current_app.config["MASTER_KEY"])
    except Exception:  # InvalidTag : le fichier chiffré a été modifié
        report["integrity_msg"] = ("Échec de vérification : fichier modifié "
                                   "(authentification AES-GCM invalide)")
        return report
    if not hashing.sha256_hex(data) == f["sha256"]:
        report["integrity_msg"] = "Échec de vérification : empreinte SHA-256 différente"
        return report
    report["integrity_ok"] = True
    report["integrity_msg"] = "Intégrité vérifiée (AES-GCM et SHA-256)"
    report["data"] = data
    owner = get_db().execute("SELECT * FROM users WHERE id = ?", (f["owner_id"],)).fetchone()
    _, ca_cert = certs.load_or_create_ca(current_app.config["PKI_DIR"])
    report["cert_ok"], report["cert_msg"] = certs.verify_certificate(
        owner["cert_pem"], ca_cert, owner["username"])
    if report["cert_ok"]:
        report["sig_ok"] = signature.verify(
            owner["cert_pem"], f["signature"], signature.message_for(f["id"], f["sha256"]))
        report["sig_msg"] = ("Signature valide : le fichier provient de " + owner["username"]
                             if report["sig_ok"] else "Signature invalide")
    else:
        report["sig_msg"] = "Signature non vérifiée (certificat refusé)"
    return report


def get_file(file_id):
    # VULNERABILITE (IDOR) : aucune vérification que l'utilisateur a le droit d'accéder au fichier
    return get_db().execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()


@bp.route("/download/<int:file_id>")
@login_required
def download(file_id):
    f = get_file(file_id)
    if f is None:
        return "Fichier introuvable", 404
    report = open_and_verify(f)
    log("telechargement", file_id, report["integrity_msg"])
    if report["integrity_ok"] and report["sig_ok"]:
        return send_file(io.BytesIO(report["data"]), as_attachment=True,
                         download_name=f["original_name"])
    return render_template("verify.html", f=f, r=report)


@bp.route("/verify/<int:file_id>")
@login_required
def verify(file_id):
    f = get_file(file_id)
    if f is None:
        return "Fichier introuvable", 404
    report = open_and_verify(f)
    log("verification", file_id, report["integrity_msg"])
    return render_template("verify.html", f=f, r=report)


@bp.route("/verify_local/<int:file_id>", methods=["POST"])
@login_required
def verify_local(file_id):
    f = get_file(file_id)
    local = request.files["file"].read()
    same = hashing.sha256_hex(local) == f["sha256"]
    flash("Le fichier local est identique à la référence de la plateforme" if same
          else "Le fichier local est DIFFÉRENT de la référence de la plateforme")
    log("verification_locale", file_id, "identique" if same else "different")
    return redirect(url_for("main.verify", file_id=file_id))


@bp.route("/share/<int:file_id>", methods=["POST"])
@login_required
def share(file_id):
    # VULNERABILITES : pas de jeton CSRF, pas de contrôle que l'utilisateur est propriétaire
    db = get_db()
    recipient = db.execute("SELECT id FROM users WHERE username = ?",
                           (request.form["recipient"],)).fetchone()
    if recipient is None:
        flash("Destinataire inconnu")
    else:
        db.execute("INSERT INTO shares(file_id, recipient_id) VALUES (?, ?)",
                   (file_id, recipient["id"]))
        db.commit()
        log("partage", file_id, "avec " + request.form["recipient"])
        flash("Fichier partagé")
    return redirect(url_for("main.files"))


@bp.route("/unshare/<int:file_id>/<int:user_id>", methods=["POST"])
@login_required
def unshare(file_id, user_id):
    db = get_db()
    db.execute("DELETE FROM shares WHERE file_id = ? AND recipient_id = ?", (file_id, user_id))
    db.commit()
    log("revocation", file_id)
    return redirect(url_for("main.files"))


# ---------- recherche et journal ----------
@bp.route("/search")
@login_required
def search():
    q = request.args.get("q", "")
    rows, error = [], None
    # VULNERABILITES : injection SQL + recherche sur les fichiers de tous les utilisateurs
    sql = "SELECT id, original_name, owner_id FROM files WHERE original_name LIKE '%" + q + "%'"
    try:
        rows = get_db().execute(sql).fetchall()
    except Exception as exc:
        error = str(exc)
    return render_template("search.html", q=q, rows=rows, error=error)


@bp.route("/audit")
def audit():
    # VULNERABILITE : journal consultable sans authentification
    rows = get_db().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("audit.html", rows=rows)
