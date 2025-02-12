import sqlite3

def insert_user(email, password):
    # Conectează-te la baza de date (va crea fișierul users.db dacă nu există)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT NOT NULL,
                        password TEXT NOT NULL
                    )''')
    
    cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
    conn.commit()
    
    conn.close()
    print("Datele au fost salvate cu succes!")


def login_user(email, password):
    print("Funcția login_user a fost apelată.")
    print(f"Email primit: {email}, Parola primită: {password}")
    
    # Conectează-te la baza de date
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Verifică utilizatorul
    cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))
    user = cursor.fetchone()
    print(f"Rezultatul interogării: {user}")
    
    # Închide conexiunea
    conn.close()
    
    # Verifică rezultatul
    if user:
        print("Autentificare reușită!")
    else:
        print("Email sau parolă incorectă!")