from app import create_app

app = create_app()

if __name__ == "__main__":
    # VULNERABILITE : debug=True expose la console Werkzeug et les traces d'erreur
    app.run(host="127.0.0.1", port=5000, debug=True)
