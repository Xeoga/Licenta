import json
import os

def load_user_session():
    """
    Citește datele utilizatorului logat din fișierul JSON 'user_session.json'.

    Returns:
        dict: cu cheile 'uuid', 'first_name', 'email'
        None: dacă fișierul nu există sau este corupt
    """
    try:
        with open("user_session.json", "r") as f:
            data = json.load(f)
            if all(k in data for k in ("uuid", "first_name", "email")):
                return data
            else:
                print("⚠️ Structura fișierului user_session.json este incompletă.")
                return None
    except FileNotFoundError:
        print("⚠️ Fișierul user_session.json nu a fost găsit.")
        return None
    except json.JSONDecodeError:
        print("⚠️ Eroare la citirea fișierului user_session.json.")
        return None
