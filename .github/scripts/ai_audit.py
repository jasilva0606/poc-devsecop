import os
import requests
import sys

def audit():
    # Cambiamos a GROQ_API_KEY
    api_key = os.getenv("GROQ_API_KEY")
    commit_msg = os.getenv("COMMIT_MSG")
    code_diff = os.getenv("CODE_DIFF")

    if not api_key:
        print("Saltando auditoría IA: GROQ_API_KEY no encontrada.")
        return

    # Prompt optimizado para seguridad
    prompt = f"""
    Actúa como un Auditor Senior de DevSecOps. Analiza el siguiente commit:
    
    Mensaje del commit: {commit_msg}
    Diferencia de código:
    {code_diff}
    
    Indica brevemente:
    1. Coherencia entre mensaje y código.
    2. Riesgos de seguridad (OWASP).
    3. Recomendación de mejora.
    """

    try:
        # Endpoint de Groq
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.3-70b-versatile", # Modelo rápido y eficiente en Groq
                "messages": [
                    {"role": "system", "content": "Eres un experto en seguridad informática y auditoría de código."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2
            }
        )
        
        result = response.json()
        print("--- REPORTE DE AUDITORÍA IA (GROQ) ---")
        print(result['choices'][0]['message']['content'])
        
    except Exception as e:
        print(f"Error contactando a Groq: {e}")

if __name__ == "__main__":
    audit()