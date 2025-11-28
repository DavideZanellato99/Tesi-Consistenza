from google import genai             
from google.genai import types  # type: ignore  
import re                              

# Inizializza il client per comunicare con il modello Gemmma
client = genai.Client(api_key="AIzaSyAIXtYquE8eH1LrtqtWkz67-RHLRmweBqA")

  
# Invia uno snippet di codice C/C++ al modello LLM Gemmma e riceve una risposta
# code_snippet: Il codice da analizzare
# response: Oggetto contenente la risposta generata dal modello
def llm(code_snippet):
    
    # Prompt da inviare al modello
    prompt = (
        "System: You are a security researcher, expert in detecting security vulnerabilities. "
        "Carefully analyze the provided C/C++ code snippet for vulnerabilities. "
        "Provide the result of the analysis only in the following itemized OUTPUT FORMAT:\n" 
        "<OUTPUT FORMAT>\n"
        "is_vulnerable: a boolean value indicating if the code snippet is vulnerable or not.\n"
        "explanation: a string containing a clear and concise explanation of your findings. If is_vulnerable is false, provide a brief explanation of why the code is not vulnerable.\n"
        "assigned_cwe: a string containing the Common Weakness Enumeration (CWE) assigned to the code snippet. If is_vulnerable is false, write N/A.\n"
        "assigned_cwe_name: a string containing the name of the the Common Weakness Enumeration (CWE) assigned to the code snippet. If is_vulnerable is false, write N/A.\n"
        "cwe_description: a string containing the description of the assigned CWE to the code snippet. If is_vulnerable is false, write N/A.\n"
        "</OUTPUT FORMAT>\n"
        "RESTRICTIONS:\n"
        "- You MUST respond with ONLY these 5 lines.\n"
        "- No extra text.\n"
        "- No markdown.\n"
        "- No blank lines before or after.\n"
        "- No commentary.\n"
        "- Do NOT change the field names.\n"
        "- Do NOT add bullet points, quotes, or formatting.\n\n"
        f"User: <code snippet to analyze>\n{code_snippet}"
    )

    # Chiamata al modello Gemma per generare la risposta con diverse configurazioni
    response = client.models.generate_content(
        #model="gemma-3-27b-it", 
        #model="gemma-3-12b-it",   
        model="gemma-3-4b-it",  
        contents=prompt,                
        config=types.GenerateContentConfig(
            temperature=0.1,
            top_p=0.9,
            seed=42
        )
    )
    return response

# Estrae e converte il testo generato dal modello in un dizionario Python
# Gestisce eventuali errori di parsing o formattazione inattesa
def parse_response(response):
    try:
        # Estrae testo grezzo
        text = response.candidates[0].content.parts[0].text.strip()

        # Dizionario finale
        data = {
            "is_vulnerable": "",
            "explanation": "",
            "assigned_cwe": "",
            "assigned_cwe_name": "",
            "cwe_description": ""
        }

        # Regex per ogni campo
        patterns = {
            "is_vulnerable": r"is_vulnerable:\s*(.+)",
            "explanation": r"explanation:\s*(.+)",
            "assigned_cwe": r"assigned_cwe:\s*(.+)",
            "assigned_cwe_name": r"assigned_cwe_name:\s*(.+)",
            "cwe_description": r"cwe_description:\s*(.+)"
        }

        for key, pattern in patterns.items():
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                # Pulizia finale
                if key == "is_vulnerable":
                    val = val.lower() == "true"
                data[key] = val

        return data

    except Exception as e:
        return {"error": f"Parsing error: {e}", "raw": text}
