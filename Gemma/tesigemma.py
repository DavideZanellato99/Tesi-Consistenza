#!/usr/bin/env python3
import csv
import json
import os
import re
import time
from promptgemma import llm, parse_response  


# ======================
# Parametri di configurazione
# ======================

csv_input = "datidomande.csv"    # Nome del file CSV di input contenente i dati da analizzare
num_ripetizioni = 5              # Numero di volte che il modello verrà chiamato per ogni snippet di codice
output_folder = "RisultatiGemma4B"      # Cartella dove salvare i risultati generati

# --- Modalità di esecuzione ---
riga_singola = None            # Se riga_singola = valore, elabora solo quella riga del CSV
riga_inizio = 1               # Riga iniziale da cui partire nel file CSV (1 = prima riga)
max_righe = 10             # Numero massimo di righe da leggere a partire da riga_inizio


# ======================
# Creazione cartella output
# ======================
# Crea la cartella di output se non esiste già
os.makedirs(output_folder, exist_ok=True)  


# ======================
# Lettura del CSV di input
# ======================
with open(csv_input, newline='', encoding='utf-8') as csvfile:
    # Legge tutto il CSV in una lista di righe
    reader = list(csv.reader(csvfile))      
    # Conta il numero totale di righe nel CSV
    total_rows = len(reader)               

    # Se è stata specificata una singola riga da processare
    if riga_singola is not None:
        # Verifica che la riga esista realmente nel file
        if riga_singola < 1 or riga_singola > total_rows:
            raise ValueError(f"La riga {riga_singola} non esiste nel CSV (ci sono {total_rows} righe).")

        # Preleva solo quella riga specifica
        righe_da_processare = [reader[riga_singola - 1]]   
        print(f"Modalità: singola riga #{riga_singola}")   

    else:
        # Calcola gli indici di inizio e fine dell’intervallo di righe da leggere
        start_idx = riga_inizio - 1
        # Evita di superare la fine del file
        end_idx = min(start_idx + max_righe, total_rows)   
        # Estrae le righe da elaborare
        righe_da_processare = reader[start_idx:end_idx]    
        print(f"Modalità: da riga {riga_inizio} a riga {end_idx} (tot: {len(righe_da_processare)})")


    # ======================
    # Ciclo sulle righe selezionate del CSV
    # ======================
    for offset, row in enumerate(righe_da_processare):
        # Calcola il numero effettivo della riga nel CSV originale
        riga_index = (riga_singola if riga_singola is not None else riga_inizio) + offset

        # Verifica che la riga contenga almeno 3 colonne (nome file, tag, codice)
        if len(row) < 3:
            print(f"Riga {riga_index} non valida (meno di 3 colonne): {row}")
            continue  # Salta la riga non valida

        # Estrae i campi principali dal CSV
        fname = row[0].strip()   # Nome del file o identificatore
        tag = row[1].strip()     # Categoria
        code = row[2].strip()    # Contenuto del codice da analizzare

        # Mostra a terminale informazioni sulla riga corrente
        print("\n" + "="*70)
        print(f"Analisi riga #{riga_index} → File: {fname} | Tag: {tag}")
        print("="*70)

        # Crea il nome del file CSV di output includendo il numero della riga
        base_name, ext = os.path.splitext(fname)
        csv_output = os.path.join(output_folder, f"{riga_index}_{base_name}{ext}.csv")

        # Apre (o crea) il file CSV di output dove verranno scritti i risultati
        with open(csv_output, 'w', newline='', encoding='utf-8') as outcsv:
            writer = csv.writer(outcsv, quoting=csv.QUOTE_ALL)

            # Scrive l’intestazione del file CSV (colonne)
            writer.writerow([
                "iteration",          # Numero dell’iterazione 
                "is_vulnerable",      # Indica se il codice è vulnerabile 
                "assigned_cwe",       # Codice CWE assegnato (se presente)
                "assigned_cwe_name",  # Nome del CWE
                "cwe_description",    # Descrizione più dettagliata del CWE
                "explanation"         # Spiegazione fornita dal modello
            ])

            # ======================
            # Ciclo sulle ripetizioni per la stessa riga
            # ======================
            for i in range(1, num_ripetizioni + 1):
                try:
                    # Chiamata al modello LLM passando il codice da analizzare
                    response = llm(code)

                    # Parsing della risposta in formato strutturato (dict)
                    data = parse_response(response)

                    # Se la risposta contiene un errore, scrive un messaggio di errore nel CSV
                    if "error" in data:
                        writer.writerow([i, "", "", "", "", f"Errore: {data['error']}"])
                    else:
                        # Scrive nel CSV i valori ottenuti dal modello
                        writer.writerow([
                            i,
                            data.get("is_vulnerable", ""),
                            data.get("assigned_cwe", ""),
                            data.get("assigned_cwe_name", ""),
                            data.get("cwe_description", ""),
                            data.get("explanation", "")
                        ])

                    # Mostra la risposta in formato JSON leggibile a terminale
                    print(f"\n--- Risposta {i} per riga #{riga_index} ({fname}) ---")
                    print(json.dumps(data, ensure_ascii=False, indent=4))
                    print(f"--- Fine risposta {i} ---\n")

                except Exception as e:
                    # Gestione di eventuali eccezioni durante la chiamata al modello o il parsing
                    print(f"Errore chiamando llm per riga #{riga_index}, ripetizione {i}: {e}")
                    writer.writerow([i, "", "", "", "", f"Exception: {e}"])  # Registra l’errore nel CSV

                print("Attendo 60 secondi prima della prossima iterazione per evitare il problema di max token inviati per minuto...")
                time.sleep(60)

        # Conferma che il file per quella riga è stato generato correttamente
        print(f"File creato: {csv_output}\n")

print("\nAnalisi completata.")
