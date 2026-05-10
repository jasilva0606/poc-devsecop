import os, sys, requests, re
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def get_safe_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retry))
    return session

def sanitize(text):
    # Lista negra de patrones sensibles
    patterns = [
        (r'(?i)password\s*[:=]\s*[^\s]+', 'password = [REDACTED]'),
        (r'(?i)api[_-]key\s*[:=]\s*[^\s]+', 'api_key = [REDACTED]'),
        (r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*', 'Bearer [REDACTED]'),
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL_REDACTED]')
    ]
    for pattern, repl in patterns:
        text = re.sub(pattern, repl, text)
    return text[:4000] # Límite de tokens

def audit():
    api_key = os.getenv("GROQ_API_KEY")
    diff = sanitize(os.getenv("CODE_DIFF", ""))
    
    if not diff or diff.strip() == "Diff too large":
        print("✅ No hay cambios significativos para auditar.")
        return 0

    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": "Eres un Auditor Senior DevSecOps. Evalúa vulnerabilidades OWASP y responde en Markdown."},
            {"role": "user", "content": f"Audita este diff:\n\n{diff}"}
        ],
        "temperature": 0.1 # Baja temperatura para mayor precisión técnica
    }

    try:
        response = get_safe_session().post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        print(response.json()['choices'][0]['message']['content'])
    except Exception as e:
        print(f"⚠️ Auditoría IA omitida: {str(e)}")
    return 0

if __name__ == "__main__":
    sys.exit(audit())