from flask import Flask, request, jsonify
import os
import psycopg2
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

UPLOAD_FOLDER = os.getenv("UPLOAD_DIR", "./server_storage/pcaps")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Creează conexiune la baza de date
def get_db_connection():
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        port=os.getenv("DB_PORT")
    )
    return conn

@app.route("/upload", methods=["POST"])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Generează un nume unic
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"capture_{timestamp}.pcap"
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    # Salvează fișierul pe server
    file.save(filepath)

    # Salvează referința în baza de date
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO pcap_metadata (filename, filepath) VALUES (%s, %s)",
            (filename, filepath)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"message": "File uploaded", "path": filepath}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)