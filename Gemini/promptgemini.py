from google import genai             
from google.genai import types  # type: ignore  
import json                             
import re                              

# Inizializza il client per comunicare con il modello Gemini
client = genai.Client(api_key="AIzaSyAIXtYquE8eH1LrtqtWkz67-RHLRmweBqA")

  
# Invia uno snippet di codice C/C++ al modello LLM Gemini e riceve una risposta strutturata in JSON.
# code_snippet: Il codice da analizzare
# response: Oggetto contenente la risposta generata dal modello
def llm(code_snippet):
    
    # Prompt da inviare al modello
    prompt = (
        "System: You are a security researcher, expert in detecting security vulnerabilities. "
        "Carefully analyze the provided C/C++ code snippet for vulnerabilities. "
        "Provide the result of the analysis as a JSON object with the following fields:\n"
        "is_vulnerable: a boolean value indicating if the code snippet is vulnerable or not.\n"
        "explanation: a string containing a clear and concise explanation of your findings. Do not include line breaks, '\\n' characters, bullet points, or numbered lists. \n"
        "assigned_cwe: a string containing the Common Weakness Enumeration (CWE) assigned to the code snippet. If the snippet is NOT vulnerable, set this field to \"N/A\".\n"
        "assigned_cwe_name: a string containing the name of the Common Weakness Enumeration (CWE) assigned to the code snippet. If the snippet is NOT vulnerable, set this field to \"N/A\".\n"
        "cwe_description: a string containing the description of the assigned CWE to the code snippet. Do not include line breaks, '\\n' characters, bullet points, or numbered lists. \n\n"
        f"User: <code snippet to analyze>\n{code_snippet}\n\n"
        "Respond ONLY with the requested JSON object (no code fences, no extra text). " 
        "Return only a valid JSON object. Ensure the JSON is syntactically correct and valid for parsing with json.loads in Python. "
        "Ensure types are correct: boolean for is_vulnerable, strings for all other fields. "
    )

    # Chiamata al modello Gemini per generare la risposta con diverse configurazioni
    response = client.models.generate_content(
        model="gemini-2.5-flash",        
        contents=prompt,                
        config=types.GenerateContentConfig(
            temperature=0.1,
            top_p=0.9,
            seed=42
        )
    )
    return response

# Estrae e converte il JSON generato dal modello in un dizionario Python.
# Gestisce eventuali errori di parsing o formattazione inattesa.
def parse_response(response):
    try:
        # Estrae il testo generato dal modello
        text = response.candidates[0].content.parts[0].text

        # Rimuove eventuali blocchi di codice Markdown (```json ... ```)
        text = re.sub(r"```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text).strip()

        # Converte il testo JSON in un dizionario Python
        return json.loads(text)
    
    except (AttributeError, IndexError):
        # Se la struttura della risposta non è quella prevista
        return {"error": "Struttura della risposta inattesa", "raw": text}
    
    except json.JSONDecodeError:
        # Se il JSON non è valido
        return {"error": "Il modello non ha restituito un JSON valido", "raw": text}
