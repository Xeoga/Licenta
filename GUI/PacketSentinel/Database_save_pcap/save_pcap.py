import os
import shutil
import sys
from datetime import datetime
import psycopg2
from fastapi import FastAPI, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse
from uuid import UUID

# Adăugăm calea pentru a importa baza de date
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from Database.database_postgreSQL import get_connection
app = FastAPI()

BASE_PCAP_DIR = "./server_storage/pcaps"
os.makedirs(BASE_PCAP_DIR, exist_ok=True)

def save_pcap_reference_to_db(uuid, filename, filepath):
    conn = get_connection()
    cursor = conn.cursor()

    insert_query = """
        INSERT INTO user_pcaps (user_uuid, filename, filepath, uploaded_at)
        VALUES (%s, %s, %s, NOW())
    """
    cursor.execute(insert_query, (str(uuid), filename, filepath))
    conn.commit()
    cursor.close()
    conn.close()

@app.post("/upload_pcap/")
def upload_pcap(uuid: UUID = Form(...), file: UploadFile = Form(...)):
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        user_dir = os.path.join(BASE_PCAP_DIR, str(uuid))
        os.makedirs(user_dir, exist_ok=True)

        new_filename = f"capture_{timestamp}.pcap"
        new_path = os.path.join(user_dir, new_filename)

        with open(new_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        save_pcap_reference_to_db(uuid, new_filename, new_path)
        return JSONResponse(status_code=200, content={"message": "Upload reușit", "filename": new_filename, "path": new_path})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
