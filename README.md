# `Sentinel`

Descriere generală
Acest proiect reprezintă începutul unui sistem integrat pentru interceptarea și analiza traficului de rețea. Momentan, include o aplicație GUI scrisă în Python, care gestionează autentificarea utilizatorilor, manipularea unei baze de date (atât SQLite, cât și PostgreSQL), fișiere sursă pentru paginile de login și înregistrare, scripturi de inițializare a bazei de date, rapoarte și diagrame UML.

Scopul final al proiectului este să ofere un mediu centralizat de colectare, analiză și raportare a datelor de trafic, având ca obiectiv:
- Interceptarea și monitorizarea pachetelor de rețea;
- Analiza și filtrarea traficului cu ajutorul unor instrumente similare Wireshark;
- Stocarea și gestionarea informațiilor într-o bază de date;
- Interfața grafică prietenoasă, pentru configurarea și vizualizarea datelor capturate.

Proiectul se află în faza inițială de dezvoltare, urmând să fie extins cu funcționalități avansate de analiză, statistică și generare de rapoarte.

## Cuprins
- [Cerințe de sistem](#cerinte-de-sistem)
- [Structura proiectului](#structura-proiectului)
- [Instalare și Configurare](#instalare-si-configurare)
- [Utilizare](#utilizare)
- [Rapoarte și Documentație](#rapoarte-si-documentatie)
- [Contribuții](#contributii)
- [Licență](#licenta)

## Cerințe de sistem

- Sistem de operare: Windows / Linux / macOS (proiectul este portabil !!!la moment nu!!!).

- Python 3.7+ (instalat și configurat corect în PATH).

Biblioteci Python:
- tkinter (în mod normal, vine preinstalat cu Python pe Windows; pe Linux poate necesita instalare suplimentară).
- sqlite3 (inclus by default în instalarea standard de Python).
- psycopg2 (sau alt driver compatibil pentru PostgreSQL, dacă folosești conexiuni la PostgreSQL).

Orice altă bibliotecă folosită (ex: scapy pentru interceptarea traficului de rețea, pandas pentru analiză, matplotlib pentru grafice etc.).

Acces la un server PostgreSQL (dacă e necesar pentru partea de stocare a datelor, altfel se poate folosi SQLite local). Fișierul `.env` unde sunt informația necesara pentru conexiune.

## Structura proiectului
#TODO
## Instalare și Configurare
#TODO
## Utilizare
#TODO
## Rapoarte și Documentație

- Rapoarte: se găsesc în folderul Rapoarte/. Acestea pot conține explicații tehnice, rezultate de testare, performanțe.

- Diagrame UML: se află în folderul UML diagrams/ și descriu arhitectura proiectului, interacțiunile dintre module, diagrama de clase.

- Propunere proiect și Întrebări (cordonator).pdf: documente oficiale legate de proiectul de licență.
## Contribuții
#TODO
## Licență
#TODO