import csv
import glob
from bert_score import score as bert_score  # type: ignore
import sacrebleu  # type: ignore
import os
import re
from openpyxl import Workbook  # type: ignore

# ============================================================
# Carica il CSV di riferimento Mitre
# ============================================================
def load_cwe_descriptions(csv_path: str) -> dict:
    cwe_dict = {}
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cwe_id = row["cwe_id"].strip()
                desc = row["cwe_description"].strip()
                cwe_dict[cwe_id] = desc
        print(f"[OK] Caricate {len(cwe_dict)} descrizioni CWE dal file '{csv_path}'")
    except FileNotFoundError:
        print(f"[ERRORE] File di riferimento '{csv_path}' non trovato!")
    return cwe_dict

# Ordina i file numericamente
def sort_files_numerically(file_list):
    def extract_number(f):
        m = re.search(r'\d+', os.path.basename(f))
        return int(m.group()) if m else float('inf')
    return sorted(file_list, key=extract_number)

# ============================================================
#   MAIN
# ============================================================

# 1. Carica il CSV di riferimento
reference_csv = "cwe_description.csv"
cwe_reference = load_cwe_descriptions(reference_csv)

# 2. Lista dei file dei risultati
input_files = glob.glob("PrimeVul/RisposteLLMPrimeVul/*.csv")
input_files = sort_files_numerically(input_files)
print(f"[INFO] Trovati {len(input_files)} file CSV di input nella cartella 'Risultati':")
for f in input_files:
    print(f"  - {f}")

# 3. Iterazione riga per riga (1..5)
for iteration_index in range(1, 6):
    print(f"\n--- Iterazione {iteration_index} ---")
    missing_cwe = set()

    # === CREA FILE EXCEL PER QUESTA ITERAZIONE ===
    wb = Workbook()

    # Foglio 1 - dettagli
    ws1 = wb.active
    ws1.title = "Dettagli"
    ws1.append([
        "Nome file", "CWE modello", "Descrizione modello",
        "Explanation modello", "CWE riferimento",
        "Descrizione riferimento"
    ])

    # Foglio 2 - metriche
    ws2 = wb.create_sheet("Metriche")
    ws2.append([
        "Nome file", "CWE modello", "CWE riferimento",
        "BERTScore descrizione", "BLEU descrizione",
        "BERTScore explanation", "BLEU explanation"
    ])

    # === ELABORAZIONE INPUT ===
    for file_path in input_files:
        file_name = os.path.basename(file_path)
        try:
            with open(file_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                print(f"[INFO] File '{file_name}' contiene {len(rows)} righe")
        except Exception as e:
            print(f"[ERRORE] Impossibile leggere '{file_name}': {e}")
            continue

        if len(rows) < iteration_index:
            print(f"[WARN] Il file '{file_name}' non ha abbastanza righe per l'iterazione {iteration_index}")
            continue

        row = rows[iteration_index - 1]

        cwe_in_file = row["assigned_cwe"].strip()
        candidate_desc = row["cwe_description"].strip()
        explanation_text = row.get("explanation", "").strip()

        # N/A → not vulnerable
        if cwe_in_file.upper() == "N/A":
            continue

        # Ottieni descrizione Mitre
        try:
            reference_desc = cwe_reference[cwe_in_file]
        except KeyError:
            missing_cwe.add(cwe_in_file)
            print(f"[WARN] CWE '{cwe_in_file}' non trovato nel CSV di riferimento")
            continue

        # ===== Calcolo BLEU & BERT per DESCRIZIONE =====
        bleu_desc = sacrebleu.corpus_bleu([candidate_desc], [[reference_desc]])
        bleu_desc_norm = round(bleu_desc.score / 100, 3)

        P, R, F1 = bert_score(
            [candidate_desc],
            [reference_desc],
            lang="en",
            model_type="bert-large-uncased"
        )
        f1_desc = round(F1.mean().item(), 3)

        # ===== Calcolo BLEU & BERT per EXPLANATION =====
        if explanation_text:
            bleu_exp = sacrebleu.corpus_bleu([explanation_text], [[reference_desc]])
            bleu_exp_norm = round(bleu_exp.score / 100, 3)

            P2, R2, F12 = bert_score(
                [explanation_text],
                [reference_desc],
                lang="en",
                model_type="bert-large-uncased"
            )
            f1_exp = round(F12.mean().item(), 3)
        else:
            bleu_exp_norm = ""
            f1_exp = ""

        # ===== Scrittura foglio 1 =====
        ws1.append([
            file_name, cwe_in_file, candidate_desc,
            explanation_text, cwe_in_file, reference_desc
        ])

        # ===== Scrittura foglio 2 =====
        ws2.append([
            file_name, cwe_in_file, cwe_in_file,
            f1_desc, bleu_desc_norm,
            f1_exp, bleu_exp_norm
        ])

    # === Salva file Excel della iterazione ===
    output_filename = f"risultati_bert_bleu_{iteration_index}.xlsx"
    try:
        wb.save(output_filename)
        print(f"[OK] File Excel salvato: {output_filename}")
    except Exception as e:
        print(f"[ERRORE] Impossibile salvare '{output_filename}': {e}")

    # === Stampa CWE mancanti ===
    if missing_cwe:
        print(f"\n[WARN] CWE mancanti nell'iterazione {iteration_index}:")
        for cwe in sorted(missing_cwe):
            print(f"  - {cwe}")

print("\n[TUTTO COMPLETATO] Analisi completata.")
