Spiegazione file che si trovano nella cartella Gemma:

Folder Metriche: cartella che contiene i risultati delle metriche per i modelli Gemma4B, Gemma12B E Gemma27B.

Folder Report: cartella che contiene i file Excel che raccolgono i risultati generati dal modello rispettivamente per la prima, seconda, terza, quarta e quinta iterazione su ciascun file presente nella cartella testSet del dataset Sven, relativi ai modelli Gemma4B, Gemma12B e Gemma27B.

Folder Risultati: cartella che contiene le risposte del LLM per tutte e cinque le iterazioni relative a ciascun file presente nella cartella testSet del dataset Sven, per i modelli Gemma4B, Gemma12B e Gemma27B.

cwec_lastest.xml: contiene l’elenco completo delle vulnerabilità e delle relative categorie CWE ed è utilizzato per il calcolo delle metriche negli script metrics_scenario2 e metrics_scenario3.

datidomande.csv: file CSV che raccoglie tutte le informazioni sui file presenti nella cartella testSet del dataset Sven. Questi dati vengono inviati al modello tramite prompt.

generaexcel.py: script Python che genera i file Excel report1.xlsx, report2.xlsx, report3.xlsx, report4.xlsx, report5.xlsx. Ognuno dei report contiene i risultati delle rispettive iterazioni per ogni file del dataset sottoposto al modello.

metrics_scenario1, metrics_scenario2, metrics_scenario3: script importati dal repository GitHub vulcan-univr/vulcan, utilizzati per il calcolo delle metriche nei diversi scenari definiti dal progetto.

promptgemma.py: script che gestisce l’interazione con il modello LLM tramite API, si occupa dell’invio del prompt e della gestione della risposta.

testigemmma.py: script che gestisce la comunicazione con il prompt del modello e consente di elaborare automaticamente tutti i file presenti nella cartella testSet.