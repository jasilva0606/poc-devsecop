#!/usr/bin/env python3
"""
AI Security Audit - Enterprise Grade (Optimizado)
Compatible con la estructura existente, con mejoras de seguridad y robustez
"""

import os
import sys
import re
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime
from typing import Optional, Dict


def get_safe_session(max_retries: int = 3) -> requests.Session:
    """Crea sesión HTTP con retry logic y backoff exponencial"""
    session = requests.Session()
    retry = Retry(
        total=max_retries,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST"]
    )
    session.mount('https://', HTTPAdapter(max_retries=retry))
    return session


def sanitize(text: str, max_length: int = 6000) -> str:
    """
    Sanitiza contenido sensible ANTES de truncar
    
    Args:
        text: Contenido a sanitizar
        max_length: Longitud máxima del output
    
    Returns:
        Texto sanitizado y truncado
    """
    if not text:
        return ""
    
    # Lista extendida de patrones sensibles
    patterns = [
        # Passwords y secrets
        (r'(?i)password\s*[:=]\s*[^\s]+', 'password=[REDACTED]'),
        (r'(?i)(api[_-]?key|secret|token)\s*[:=]\s*[^\s]+', r'\1=[REDACTED]'),
        
        # Bearer tokens
        (r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*', 'Bearer [REDACTED]'),
        (r'Authorization:\s*Bearer\s+[^\s]+', 'Authorization: Bearer [REDACTED]'),
        
        # Private keys
        (r'-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----', 
         '[PRIVATE_KEY_REDACTED]'),
        
        # Emails
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL]'),
        
        # AWS keys
        (r'AKIA[0-9A-Z]{16}', '[AWS_ACCESS_KEY_REDACTED]'),
        
        # JWT tokens
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', '[JWT_REDACTED]'),
        
        # URLs con credentials
        (r'https?://[^:]+:[^@]+@', 'https://[CREDENTIALS_REDACTED]@'),
    ]
    
    # Aplicar sanitización
    sanitized = text
    for pattern, repl in patterns:
        sanitized = re.sub(pattern, repl, sanitized, flags=re.DOTALL | re.IGNORECASE)
    
    # Truncar al límite
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "\n\n... [TRUNCADO - contenido demasiado largo]"
    
    return sanitized


def calculate_risk_metrics(diff: str) -> Dict[str, any]:
    """Calcula métricas de riesgo del diff"""
    
    lines = diff.split('\n')
    
    metrics = {
        'lines_added': len([l for l in lines if l.startswith('+') and not l.startswith('+++')]),
        'lines_removed': len([l for l in lines if l.startswith('-') and not l.startswith('---')]),
        'files_changed': len(set(re.findall(r'diff --git a/(.*?) b/', diff))),
        'has_auth_changes': bool(re.search(r'(auth|login|password|credential)', diff, re.IGNORECASE)),
        'has_crypto_changes': bool(re.search(r'(encrypt|decrypt|cipher|hash|sha256|md5)', diff, re.IGNORECASE)),
        'has_db_changes': bool(re.search(r'(query|execute|prepare|sql)', diff, re.IGNORECASE)),
        'has_network_changes': bool(re.search(r'(curl|request|socket|http|fetch)', diff, re.IGNORECASE)),
        'has_file_ops': bool(re.search(r'(fopen|file_put_contents|unlink|chmod)', diff, re.IGNORECASE)),
    }
    
    # Calcular risk score (0-20)
    risk_score = 0
    risk_score += min(metrics['lines_added'] // 10, 5)
    risk_score += 4 if metrics['has_auth_changes'] else 0
    risk_score += 3 if metrics['has_crypto_changes'] else 0
    risk_score += 3 if metrics['has_db_changes'] else 0
    risk_score += 2 if metrics['has_network_changes'] else 0
    risk_score += 2 if metrics['has_file_ops'] else 0
    
    metrics['risk_score'] = risk_score
    
    if risk_score >= 12:
        metrics['risk_level'] = 'CRITICAL'
    elif risk_score >= 8:
        metrics['risk_level'] = 'HIGH'
    elif risk_score >= 4:
        metrics['risk_level'] = 'MEDIUM'
    else:
        metrics['risk_level'] = 'LOW'
    
    return metrics


def call_groq_api(
    api_key: str,
    diff: str,
    metrics: Dict,
    timeout: int = 30
) -> Optional[str]:
    """
    Llama a Groq API con manejo robusto de errores
    
    Args:
        api_key: Groq API key
        diff: Código diff sanitizado
        metrics: Métricas de riesgo
        timeout: Timeout en segundos
    
    Returns:
        Análisis de seguridad o None si falla
    """
    
    system_prompt = """Eres un Auditor Senior de DevSecOps con 15+ años de experiencia.
Especializado en OWASP Top 10, CWE, SANS Top 25, y Secure Coding Practices.
Analiza cambios de código identificando vulnerabilidades explotables.
Responde SIEMPRE en formato Markdown estructurado."""

    user_prompt = f"""Analiza este diff desde una perspectiva de seguridad:

**MÉTRICAS DE RIESGO:**
- Risk Level: {metrics['risk_level']}
- Risk Score: {metrics['risk_score']}/20
- Líneas modificadas: +{metrics['lines_added']} -{metrics['lines_removed']}
- Archivos cambiados: {metrics['files_changed']}
- Cambios en Auth: {'✅' if metrics['has_auth_changes'] else '❌'}
- Cambios en Crypto: {'✅' if metrics['has_crypto_changes'] else '❌'}
- Cambios en DB: {'✅' if metrics['has_db_changes'] else '❌'}

**DIFF:**
```diff
{diff}
```

Proporciona análisis en este formato:

## 1. 🔍 COHERENCIA
¿Los cambios son coherentes y necesarios?

## 2. 🚨 VULNERABILIDADES DETECTADAS

### CRITICAL
- [Descripción específica con CWE/OWASP reference]

### HIGH
- [Descripción específica]

### MEDIUM
- [Descripción específica]

## 3. 💡 RECOMENDACIONES
1. [Acción concreta]
2. [Acción concreta]

## 4. ✅ VALIDACIONES FALTANTES
- Input validation
- Output encoding
- Sanitización

Sé específico, técnico y prioriza por severidad."""

    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 2000,
        "top_p": 0.9
    }

    try:
        session = get_safe_session()
        response = session.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=timeout
        )
        
        response.raise_for_status()
        
        result = response.json()
        
        # Validar respuesta
        if 'error' in result:
            error_msg = result.get('error', {}).get('message', 'Unknown error')
            print(f"❌ Groq API Error: {error_msg}")
            return None
        
        if 'choices' not in result or not result['choices']:
            print(f"❌ Respuesta inesperada de Groq API")
            return None
        
        return result['choices'][0]['message']['content']
        
    except requests.exceptions.Timeout:
        print(f"❌ Timeout contactando Groq API ({timeout}s)")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP Error {e.response.status_code}: {e.response.text[:200]}")
        return None
    except Exception as e:
        print(f"❌ Error inesperado: {str(e)}")
        return None


def generate_markdown_report(
    analysis: str,
    metrics: Dict,
    commit_sha: str,
    branch: str,
    actor: str
) -> str:
    """Genera reporte en Markdown"""
    
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    report = f"""# 🤖 AI Security Audit Report

**Generated**: {timestamp}
**Commit**: `{commit_sha[:8]}`
**Branch**: `{branch}`
**Author**: `{actor}`
**Risk Level**: **{metrics['risk_level']}** ({metrics['risk_score']}/20)

---

## 📊 Change Metrics

| Metric | Value |
|--------|------:|
| Files Changed | {metrics['files_changed']} |
| Lines Added | {metrics['lines_added']} |
| Lines Removed | {metrics['lines_removed']} |
| Risk Score | {metrics['risk_score']}/20 |

### Risk Indicators

| Category | Detected |
|----------|:--------:|
| 🔐 Authentication/Authorization | {'✅' if metrics['has_auth_changes'] else '❌'} |
| 🔒 Cryptography | {'✅' if metrics['has_crypto_changes'] else '❌'} |
| 🗄️ Database Operations | {'✅' if metrics['has_db_changes'] else '❌'} |
| 🌐 Network Operations | {'✅' if metrics['has_network_changes'] else '❌'} |
| 📁 File Operations | {'✅' if metrics['has_file_ops'] else '❌'} |

---

{analysis}

---

*This analysis was generated by AI. Manual security review is recommended for production deployments.*
"""
    
    return report


def audit() -> int:
    """
    Función principal de auditoría
    
    Returns:
        Exit code (0 = success, 1 = failure)
    """
    
    # Obtener variables de entorno
    api_key = os.getenv("GROQ_API_KEY")
    raw_diff = os.getenv("CODE_DIFF", "")
    
    commit_sha = os.getenv("GITHUB_SHA", "unknown")
    branch = os.getenv("GITHUB_REF_NAME", "unknown")
    actor = os.getenv("GITHUB_ACTOR", "unknown")
    
    # Validar API key
    if not api_key:
        print("⚠️  GROQ_API_KEY no encontrada")
        print("ℹ️  Configure el secret para habilitar análisis con IA")
        print("✅ Pipeline continúa sin auditoría IA")
        return 0
    
    # Sanitizar diff
    diff = sanitize(raw_diff, max_length=6000)
    
    # Validar que hay contenido
    if not diff or diff.strip() in ["", "Diff sanitizado", "Diff too large"]:
        print("ℹ️  No hay cambios significativos para auditar")
        print("✅ Pipeline continúa")
        return 0
    
    print("\n" + "="*70)
    print("🤖 INICIANDO AUDITORÍA DE SEGURIDAD CON IA (GROQ)")
    print("="*70 + "\n")
    
    # Calcular métricas
    print("📊 Calculando métricas de riesgo...")
    metrics = calculate_risk_metrics(diff)
    
    print(f"   • Risk Level: {metrics['risk_level']}")
    print(f"   • Risk Score: {metrics['risk_score']}/20")
    print(f"   • Files Changed: {metrics['files_changed']}")
    print(f"   • Lines: +{metrics['lines_added']} -{metrics['lines_removed']}\n")
    
    # Llamar a Groq API
    print("🔄 Consultando Groq LLM...")
    analysis = call_groq_api(api_key, diff, metrics)
    
    if not analysis:
        print("⚠️  No se pudo completar auditoría IA")
        print("ℹ️  Revisar logs para más detalles")
        print("✅ Pipeline continúa (auditoría no es bloqueante)")
        return 0
    
    # Generar reporte
    print("\n📝 Generando reporte...")
    report = generate_markdown_report(analysis, metrics, commit_sha, branch, actor)
    
    # Guardar reporte
    report_file = 'ai-audit-report.md'
    try:
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"✅ Reporte guardado: {report_file}\n")
    except Exception as e:
        print(f"⚠️  Error guardando reporte: {e}")
    
    # Mostrar análisis en consola
    print("="*70)
    print("📋 ANÁLISIS DE SEGURIDAD")
    print("="*70)
    print(analysis)
    print("="*70 + "\n")
    
    # Determinar exit code basado en severidad
    # Por ahora no fallamos el pipeline, solo informamos
    if 'CRITICAL' in analysis.upper():
        print("🚨 Se detectaron vulnerabilidades CRÍTICAS")
        print("⚠️  Revisar el reporte antes de hacer merge")
    elif 'HIGH' in analysis.upper():
        print("⚠️  Se detectaron vulnerabilidades HIGH")
        print("ℹ️  Considerar revisión de seguridad")
    else:
        print("✅ No se detectaron vulnerabilidades críticas")
    
    print(f"\n📊 Risk Level: {metrics['risk_level']}")
    print(f"📄 Reporte completo en: {report_file}\n")
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(audit())
    except KeyboardInterrupt:
        print("\n⚠️  Auditoría cancelada")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error fatal: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
