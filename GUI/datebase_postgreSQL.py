import psycopg2

def insert_user(email, password):
    # Conectează-te la baza de date PostgreSQL
    # Înlocuiește valorile cu cele reale din setup-ul tău
    conn = psycopg2.connect(
        host="localhost",      # sau IP server
        database="mydatabase", # numele bazei de date
        user="myuser",         # user DB
        password="mypassword", # parola
        port="5432"            # portul default PostgreSQL
    )
    cursor = conn.cursor()
    
    # Creează tabela dacă nu există (folosim SERIAL în loc de AUTOINCREMENT)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL
        )
    ''')

    # În PostgreSQL folosim placeholderul %s în loc de ?
    cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, password))
    conn.commit()
    
    # Închide conexiunea
    conn.close()
    print("Datele au fost salvate cu succes!")


def login_user(email, password):
    print("Funcția login_user a fost apelată.")
    print(f"Email primit: {email}, Parola primită: {password}")

    # Conectează-te la baza de date PostgreSQL
    conn = psycopg2.connect(
        host="localhost",
        database="mydatabase",
        user="myuser",
        password="mypassword",
        port="5432"
    )
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
