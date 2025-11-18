from application import create_app, setup_database

app = create_app()

if __name__ == '__main__':
    setup_database(app) # Ensures DB and Admin user exist
    app.run(debug=True)