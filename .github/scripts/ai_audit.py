#!/usr/bin/env python3
"""
AI Security Audit — Enterprise Grade (Fixed)

Correcciones aplicadas vs versión original:
  - FIX-1: Validación de formato de GROQ_API_KEY antes de usarla
  - FIX-2: Límite explícito de tamaño de diff (truncado en el workflow,
            pero con segunda línea de defensa aquí)
  - FIX-3: actor/branch/sha saneados antes de incluirlos en el reporte
  - FIX-4: Timeout configurable por env var
  - FIX-5: Exit code diferenciado: 0=ok, 1=error fatal, 2=vulnerabilidades críticas
            (permite que el caller decida si bloquear)
  - FIX-6: Logging estructurado en lugar de prints sueltos
"""

import os
import re
import sys
import json
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime, timezone
from typing import Optional


# ── Logging estructurado ────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

# ── Constantes ───────────────────────────────────────────────────────────────
MAX_DIFF_BYTES     = 6_000        # máximo de caracteres enviados al LLM
MAX_REPORT_BYTES   = 50_000       # tamaño máximo del reporte final en disco
GROQ_API_URL       = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL         = "llama-3.3-70b-versatile"

# Patrón mínimo de formato para una Groq API key legítima
# (evita enviar valores claramente inválidos o accidentalmente vacíos)
GROQ_KEY_PATTERN   = re.compile(r'^gsk_[A-Za-z0-9]{40,}$')


# ── Sesión HTTP con retry ─────────────────────────────────────────────────────
def get_safe_session(max_retries: int = 3) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=max_retries,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST"],
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


# ── Sanitización ─────────────────────────────────────────────────────────────
def sanitize_text(text: str, max_length: int = MAX_DIFF_BYTES) -> str:
    """
    Elimina patrones sensibles del texto y lo trunca al límite indicado.
    Sanitiza ANTES de truncar para no cortar a la mitad un patrón sensible.
    """
    if not text:
        return ""

    patterns = [
        (r'(?i)password\s*[:=]\s*\S+',                         'password=[REDACTED]'),
        (r'(?i)(api[_-]?key|secret|token)\s*[:=]\s*\S+',       r'\1=[REDACTED]'),
        (r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',                    'Bearer [REDACTED]'),
        (r'Authorization:\s*Bearer\s+\S+',                     'Authorization: Bearer [REDACTED]'),
        (r'-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----',
         '[PRIVATE_KEY_REDACTED]'),
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',   '[EMAIL]'),
        (r'AKIA[0-9A-Z]{16}',                                   '[AWS_KEY_REDACTED]'),
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', '[JWT_REDACTED]'),
        (r'https?://[^:]+:[^@]+@',                              'https://[CREDENTIALS_REDACTED]@'),
        # FIX-3: limpiar también caracteres de control que podrían escapar del JSON
        (r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]',                 ''),
    ]

    sanitized = text
    for pattern, replacement in patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.DOTALL | re.IGNORECASE)

    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "\n\n... [TRUNCADO]"

    return sanitized


def sanitize_metadata(value: str, max_len: int = 200) -> str:
    """
    Sanitiza campos de metadatos (branch, actor, sha) que van al reporte.
    Solo permite caracteres alfanuméricos, guiones, barras y puntos.
    """
    clean = re.sub(r'[^a-zA-Z0-9/_\-.]', '_', str(value))
    return clean[:max_len]


# ── Métricas de riesgo ────────────────────────────────────────────────────────
def calculate_risk_metrics(diff: str) -> dict:
    lines = diff.split("\n")
    metrics = {
        "lines_added":        len([l for l in lines if l.startswith("+") and not l.startswith("+++")]),
        "lines_removed":      len([l for l in lines if l.startswith("-") and not l.startswith("---")]),
        "files_changed":      len(set(re.findall(r'diff --git a/(.*?) b/', diff))),
        "has_auth_changes":   bool(re.search(r'(auth|login|password|credential)', diff, re.I)),
        "has_crypto_changes": bool(re.search(r'(encrypt|decrypt|cipher|hash|sha256|md5)', diff, re.I)),
        "has_db_changes":     bool(re.search(r'(query|execute|prepare|sql)', diff, re.I)),
        "has_network_changes":bool(re.search(r'(curl|request|socket|http|fetch)', diff, re.I)),
        "has_file_ops":       bool(re.search(r'(fopen|file_put_contents|unlink|chmod)', diff, re.I)),
    }

    score = 0
    score += min(metrics["lines_added"] // 10, 5)
    score += 4 if metrics["has_auth_changes"]    else 0
    score += 3 if metrics["has_crypto_changes"]  else 0
    score += 3 if metrics["has_db_changes"]      else 0
    score += 2 if metrics["has_network_changes"] else 0
    score += 2 if metrics["has_file_ops"]        else 0

    metrics["risk_score"] = score
    if score >= 12:
        metrics["risk_level"] = "CRITICAL"
    elif score >= 8:
        metrics["risk_level"] = "HIGH"
    elif score >= 4:
        metrics["risk_level"] = "MEDIUM"
    else:
        metrics["risk_level"] = "LOW"

    return metrics


# ── Llamada a Groq API ────────────────────────────────────────────────────────
def call_groq_api(
    api_key: str,
    diff: str,
    metrics: dict,
    timeout: int = 30,
) -> Optional[str]:
    """
    Llama a Groq API. Retorna el texto del análisis o None si falla.
    FIX-1: La validación de formato ya se hizo antes de llegar aquí.
    """
    system_prompt = (
        "Eres un Auditor Senior de DevSecOps con 15+ años de experiencia. "
        "Especializado en OWASP Top 10, CWE, SANS Top 25, y Secure Coding Practices. "
        "Analiza cambios de código identificando vulnerabilidades explotables. "
        "Responde SIEMPRE en formato Markdown estructurado."
    )

    user_prompt = f"""Analiza este diff desde una perspectiva de seguridad:

**MÉTRICAS DE RIESGO:**
- Risk Level: {metrics["risk_level"]}
- Risk Score: {metrics["risk_score"]}/20
- Líneas modificadas: +{metrics["lines_added"]} -{metrics["lines_removed"]}
- Archivos cambiados: {metrics["files_changed"]}
- Cambios en Auth: {"✅" if metrics["has_auth_changes"] else "❌"}
- Cambios en Crypto: {"✅" if metrics["has_crypto_changes"] else "❌"}
- Cambios en DB: {"✅" if metrics["has_db_changes"] else "❌"}

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
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "temperature": 0.1,
        "max_tokens":  2000,
        "top_p":       0.9,
    }

    try:
        session  = get_safe_session()
        response = session.post(
            GROQ_API_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type":  "application/json",
            },
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        result = response.json()

        if "error" in result:
            log.error("Groq API error: %s", result["error"].get("message", "unknown"))
            return None

        if not result.get("choices"):
            log.error("Respuesta inesperada de Groq (sin choices)")
            return None

        return result["choices"][0]["message"]["content"]

    except requests.exceptions.Timeout:
        log.error("Timeout contactando Groq API (%ds)", timeout)
        return None
    except requests.exceptions.HTTPError as exc:
        log.error("HTTP %s: %s", exc.response.status_code, exc.response.text[:200])
        return None
    except Exception as exc:                         # noqa: BLE001
        log.error("Error inesperado llamando a Groq: %s", exc)
        return None


# ── Generación de reporte ─────────────────────────────────────────────────────
def generate_markdown_report(
    analysis: str,
    metrics: dict,
    commit_sha: str,
    branch: str,
    actor: str,
) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""# 🤖 AI Security Audit Report

**Generated**: {timestamp}
**Commit**: `{commit_sha[:8]}`
**Branch**: `{branch}`
**Author**: `{actor}`
**Risk Level**: **{metrics["risk_level"]}** ({metrics["risk_score"]}/20)

---

## 📊 Change Metrics

| Metric | Value |
|--------|------:|
| Files Changed | {metrics["files_changed"]} |
| Lines Added | {metrics["lines_added"]} |
| Lines Removed | {metrics["lines_removed"]} |
| Risk Score | {metrics["risk_score"]}/20 |

### Risk Indicators

| Category | Detected |
|----------|:--------:|
| 🔐 Authentication/Authorization | {"✅" if metrics["has_auth_changes"]    else "❌"} |
| 🔒 Cryptography                 | {"✅" if metrics["has_crypto_changes"]  else "❌"} |
| 🗄️ Database Operations         | {"✅" if metrics["has_db_changes"]      else "❌"} |
| 🌐 Network Operations           | {"✅" if metrics["has_network_changes"] else "❌"} |
| 📁 File Operations              | {"✅" if metrics["has_file_ops"]        else "❌"} |

---

{analysis}

---

*This analysis was generated by AI and should be reviewed by a human security engineer
before making decisions in production. Manual review is always recommended.*
"""


# ── Función principal ─────────────────────────────────────────────────────────
def audit() -> int:
    """
    Retorna:
      0 — auditoría completada sin vulnerabilidades críticas
      1 — error fatal (no se pudo completar la auditoría)
      2 — FIX-5: vulnerabilidades CRÍTICAS detectadas (permite bloquear el pipeline)
    """

    # ── Leer variables de entorno ──────────────────────────────────────────────
    api_key  = os.getenv("GROQ_API_KEY", "").strip()
    raw_diff = os.getenv("CODE_DIFF", "")

    # FIX-3: sanitizar metadatos antes de usarlos en cualquier salida
    commit_sha = sanitize_metadata(os.getenv("GITHUB_SHA",       "unknown"))
    branch     = sanitize_metadata(os.getenv("GITHUB_REF_NAME",  "unknown"))
    actor      = sanitize_metadata(os.getenv("GITHUB_ACTOR",     "unknown"))
    timeout    = int(os.getenv("GROQ_TIMEOUT", "30"))

    # ── FIX-1: Validar formato de API key ─────────────────────────────────────
    if not api_key:
        log.info("GROQ_API_KEY no configurada — omitiendo auditoría IA")
        log.info("Configure el secret en Settings > Secrets para habilitarla")
        return 0

    if not GROQ_KEY_PATTERN.match(api_key):
        log.warning(
            "GROQ_API_KEY tiene formato inesperado (esperado: gsk_...). "
            "Verificar que el secret está correctamente configurado."
        )
        # No fallamos el pipeline por esto, pero sí avisamos
        return 0

    # ── FIX-2: Sanitizar y truncar diff ───────────────────────────────────────
    diff = sanitize_text(raw_diff, max_length=MAX_DIFF_BYTES)

    if not diff.strip():
        log.info("Sin cambios significativos para auditar — pipeline continúa")
        return 0

    # ── Ejecutar auditoría ─────────────────────────────────────────────────────
    log.info("="*70)
    log.info("INICIANDO AUDITORÍA DE SEGURIDAD CON IA (GROQ / %s)", GROQ_MODEL)
    log.info("="*70)

    metrics = calculate_risk_metrics(diff)
    log.info(
        "Métricas — Risk: %s (%s/20)  Files: %s  Lines: +%s/-%s",
        metrics["risk_level"], metrics["risk_score"],
        metrics["files_changed"], metrics["lines_added"], metrics["lines_removed"],
    )

    log.info("Consultando Groq LLM...")
    analysis = call_groq_api(api_key, diff, metrics, timeout=timeout)

    if not analysis:
        log.warning("No se pudo completar la auditoría IA — revisar logs")
        log.info("Pipeline continúa (auditoría IA no es gate duro)")
        return 0

    # ── Generar y guardar reporte ──────────────────────────────────────────────
    report = generate_markdown_report(analysis, metrics, commit_sha, branch, actor)

    # FIX: limitar tamaño del reporte en disco
    if len(report) > MAX_REPORT_BYTES:
        report = report[:MAX_REPORT_BYTES] + "\n\n... [REPORTE TRUNCADO]\n"

    report_file = "ai-audit-report.md"
    try:
        with open(report_file, "w", encoding="utf-8") as fh:
            fh.write(report)
        log.info("Reporte guardado en: %s", report_file)
    except OSError as exc:
        log.warning("No se pudo guardar el reporte: %s", exc)

    # ── Mostrar resumen en consola ─────────────────────────────────────────────
    log.info("="*70)
    log.info("ANÁLISIS DE SEGURIDAD")
    log.info("="*70)
    print(analysis)           # print deliberado: va al step summary de Actions
    log.info("="*70)

    # ── FIX-5: Exit code diferenciado ─────────────────────────────────────────
    analysis_upper = analysis.upper()
    if "CRITICAL" in analysis_upper:
        log.warning("🚨 Vulnerabilidades CRÍTICAS detectadas — revisar antes de merge")
        log.info("Risk Level: %s | Reporte: %s", metrics["risk_level"], report_file)
        # Retornar 2 permite que el caller (workflow) decida si bloquear o solo avisar
        return 2

    if "HIGH" in analysis_upper:
        log.warning("⚠️ Vulnerabilidades HIGH detectadas — considerar revisión")
    else:
        log.info("✅ No se detectaron vulnerabilidades críticas")

    log.info("Risk Level: %s | Reporte: %s", metrics["risk_level"], report_file)
    return 0


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        sys.exit(audit())
    except KeyboardInterrupt:
        log.warning("Auditoría cancelada por el usuario")
        sys.exit(130)
    except Exception as exc:                          # noqa: BLE001
        log.critical("Error fatal: %s", exc, exc_info=True)
        sys.exit(1)