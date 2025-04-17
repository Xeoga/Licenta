import psycopg2
import bcrypt
import os
import uuid
from dotenv import load_dotenv
import hashlib
import subprocess
import sys
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
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

def hash_password(password):
    """ Hash simplu cu SHA-256 fără salt """
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def insert_user(email, password, first_name, last_name):
    """Funcție de înregistrare a unui utilizator în baza de date."""
    conn = get_connection()
    cursor = conn.cursor()

# Creează tabela dacă nu există (folosind tipul UUID pentru id):
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            first_name VARCHAR(255) NOT NULL,
            last_name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL
        )
    ''')

    # Generează un UUID v4
    user_id = str(uuid.uuid4())

    # Criptează parola
    hashed_password = hash_password(password)

    # Inserează datele (ai grijă să transmiți user_id, email și password)
    cursor.execute(
        "INSERT INTO users (id, first_name, last_name, email, password) VALUES (%s, %s, %s, %s, %s)",
        (user_id, first_name, last_name, email, hashed_password)
    )
    conn.commit()
    
    cursor.close()
    conn.close()
    
    print("Datele au fost salvate cu succes!")

def login_user(email, password):
    print("Funcția login_user a fost apelată.")
    print(f"Email primit: {email}, Parola primită: {password}")

    conn = get_connection()
    cursor = conn.cursor()

    # Hashuiește parola introdusă
    hashed_password = hash_password(password)

    # Caută utilizatorul după email și parolă hashuită
    cursor.execute("SELECT id, first_name FROM users WHERE email = %s AND password = %s", (email, hashed_password))
    user = cursor.fetchone()

    if user:
        user_uuid = user[0]
        first_name = user[1]
        # 🔽 Salvare într-un fișier JSON
        session_data = {
             "uuid": user_uuid,
            "first_name": first_name,
               "email": email
            }
        with open("user_session.json", "w") as f:
             json.dump(session_data, f)
        # 🔽 Pornește aplicația principală
        subprocess.Popen(["python", "PacketSentinel/main.py"])

        conn.close()
        return user_uuid, first_name  # trimite UUID și prenumele

    else:
        print("❌ Email sau parolă incorecte.")
        conn.close()
        return None, None

