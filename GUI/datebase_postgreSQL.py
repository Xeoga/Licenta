import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

def get_connection():
    """
    Creează și returnează o conexiune psycopg2
    folosind variabilele de mediu din .env
    """
    db_host = os.environ.get("DB_HOST")
    db_port = os.environ.get("DB_PORT")
    db_name = os.environ.get("DB_NAME")
    db_user = os.environ.get("DB_USER")
    db_pass = os.environ.get("DB_PASS")

    conn = psycopg2.connect(
        host=db_host,
        database=db_name,
        user=db_user,
        password=db_pass,
        port=db_port
    )
    return conn

def insert_user(email, password):
    """Funcție de înregistrare a unui utilizator în baza de date."""
    conn = get_connection()
    cursor = conn.cursor()

    # Creează tabela dacă nu există:
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL
        )
    ''')

    # Inserează datele
    cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, password))
    conn.commit()
    
    cursor.close()
    conn.close()
    
    print("Datele au fost salvate cu succes!")

def login_user(email, password):
    '''

    '''
    print("Funcția login_user a fost apelată.")
    print(f"Email primit: {email}, Parola primită: {password}")
    conn = get_connection()
    cursor = conn.cursor()
    # Interoghează utilizatorul
    cursor.execute("SELECT * FROM users WHERE email = %s AND password = %s", (email, password))
    user = cursor.fetchone()
    print(f"Rezultatul interogării: {user}")
    # Închide conexiunea
    conn.close()
    
    if user:
        print("Autentificare reușită!")
    else:
        print("Email sau parolă incorectă!")
