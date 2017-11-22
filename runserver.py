from app import make_app

app = make_app()

if __name__ == "__main__":
    app.run("0.0.0.0", port=80)
