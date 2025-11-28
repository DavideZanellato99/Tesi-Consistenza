#!/usr/bin/env python3
import re
from pathlib import Path
import pandas as pd  # type:ignore


def extract_prefix_number(filename: str) -> int:
    m = re.match(r'^(\d+)_', filename)
    return int(m.group(1)) if m else 999999


def extract_base_name(filename: str) -> str:
    name = Path(filename).name
    if name.lower().endswith('.csv'):
        name = name[:-4]
    name = re.sub(r'^\d+_', '', name)
    return name


def normalize_cwe_format(text: str) -> str:
    text = text.upper().strip()
    if text == "N/A":
        return "NOT VULNERABLE"
    return re.sub(r'CWE-0*([1-9]\d*)', r'CWE-\1', text)


def extract_actual_cwe_from_filename(basename: str) -> str:
    if re.search(r'not[_\-]?vulnerable', basename, re.IGNORECASE):
        return "NOT VULNERABLE"
    m = re.search(r'cwe-\d+', basename, re.IGNORECASE)
    if m:
        return normalize_cwe_format(m.group(0))
    return ""


def read_iteration_cwe(path: Path, iteration: int) -> str:
    """Legge solo la riga 'iteration' (1-5) dalla terza colonna."""
    try:
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
    except Exception as e:
        print(f"Errore nella lettura di {path.name}: {e}")
        return ""

    if len(df.columns) < 3:
        print(f"Attenzione: {path.name} non ha abbastanza colonne.")
        return ""

    third_col = df.columns[2]

    if len(df) < iteration:
        print(f"Attenzione: {path.name} non ha {iteration} righe.")
        return ""

    value = str(df.iloc[iteration - 1][third_col]).strip()
    return normalize_cwe_format(value)


def build_reports(input_folder: Path, output_folder: Path):
    for iteration in range(1, 6):
        rows = []

        for f in input_folder.iterdir():
            if not f.is_file() or f.suffix.lower() != '.csv':
                continue

            prefix_num = extract_prefix_number(f.name)
            basename = extract_base_name(f.name)
            actual_cwe = extract_actual_cwe_from_filename(basename)
            found_cwe = read_iteration_cwe(f, iteration)

            rows.append({
                "Order": prefix_num + 1,
                "File Name": basename,
                "Found CWE": found_cwe,
                "Actual CWE": actual_cwe
            })

        df_out = pd.DataFrame(rows, columns=["Order", "File Name", "Found CWE", "Actual CWE"])
        df_out = df_out.sort_values("Order").drop(columns=["Order"]).reset_index(drop=True)

        output_excel = output_folder / f"report{iteration}.xlsx"
        with pd.ExcelWriter(output_excel, engine='openpyxl') as writer:
            df_out.to_excel(writer, index=False, sheet_name=f'report{iteration}')

        print(f"✅ Creato {output_excel} ({len(df_out)} righe)")


if __name__ == "__main__":

    input_folder = Path(r"RisultatiGemma4B")       # cartella con i CSV
    output_folder = Path(r"ReportGemma4B")   # cartella dove salvare i report

    # Crea la cartella di output se non esiste
    output_folder.mkdir(parents=True, exist_ok=True)

    build_reports(input_folder, output_folder)
