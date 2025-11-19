"""
Crea un CSV (senza header) con tre colonne:
 - colonna 1: nome del file con estensione
 - colonna 2: 'not_vulnerable' se il nome del file contiene 'not_vulnerable',
              altrimenti la prima occorrenza 'CWE-<numero>' se presente,
              altrimenti 'UNKNOWN'
 - colonna 3: tutto il contenuto del file su una sola riga 

Uso:
    python3 make_csv.py /path/to/folder output.csv
"""

import os
import re
import csv
import argparse

CWE_RE = re.compile(r'CWE-\d+', re.IGNORECASE)

def tag_from_filename(name: str) -> str:
    lower = name.lower()
    if 'not_vulnerable' in lower:
        return 'not_vulnerable'
    m = CWE_RE.search(name)
    if m:
        return m.group(0).upper()
    return 'UNKNOWN'

def process_folder(folder: str, out_csv: str, encoding: str = 'utf-8'):
    entries = sorted(os.listdir(folder))
    files = [f for f in entries if os.path.isfile(os.path.join(folder, f))]
    with open(out_csv, 'w', newline='', encoding=encoding) as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
        for fname in files:
            fpath = os.path.join(folder, fname)
            tag = tag_from_filename(fname)
            try:
                with open(fpath, 'r', encoding=encoding, errors='replace') as fh:
                    content = fh.read().replace('\n', ' ').replace('\r', ' ')
            except Exception as e:
                try:
                    with open(fpath, 'rb') as fh:
                        raw = fh.read()
                    content = raw.decode(encoding, errors='replace').replace('\n', ' ').replace('\r', ' ')
                except Exception as e2:
                    content = f"<ERROR reading file: {e2}>"
            writer.writerow([fname, tag, content])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Crea CSV da file in una cartella (no header, contenuto su una sola riga).'
    )
    parser.add_argument('folder', help='Cartella contenente i file')
    parser.add_argument('output_csv', help='Percorso file CSV di output')
    parser.add_argument('--encoding', default='utf-8', help='Encoding da usare per leggere/scrivere (default utf-8)')
    args = parser.parse_args()

    if not os.path.isdir(args.folder):
        print(f"Errore: '{args.folder}' non è una cartella valida.")
        raise SystemExit(1)

    process_folder(args.folder, args.output_csv, encoding=args.encoding)
    num_files = len([f for f in os.listdir(args.folder) if os.path.isfile(os.path.join(args.folder, f))])
    print(f"Creato {args.output_csv} con {num_files} righe.")
