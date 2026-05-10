#!/usr/bin/env python3
"""
AI Security Audit — Enterprise Grade (PoC PHP Optimized)
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
# Subido a 20KB para mejor contexto en PHP base
MAX_DIFF_BYTES     = 20_000        
MAX_REPORT_BYTES   = 50_000       
GROQ_API_URL       = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL         = "llama-3.3-70b-versatile"

# Patrón mínimo de formato para Groq
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
    if not text: return ""

    patterns = [
        (r'(?i)password\s*[:=]\s*\S+',                         'password=[REDACTED]'),
        (r'(?i)(api[_-]?key|secret|token)\s*[:=]\s*\S+',       r'\1=[REDACTED]'),
        (r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',                    'Bearer [REDACTED]'),
        (r'-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----', '[PRIVATE_KEY_REDACTED]'),
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',   '[EMAIL]'),
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', '[JWT_REDACTED]'),
        (r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]',                 ''),
    ]

    sanitized = text
    for pattern, replacement in patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.DOTALL | re.IGNORECASE)

    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "\n\n... [DIFF TRUNCADO POR TAMAÑO]"

    return sanitized

def sanitize_metadata(value: str, max_len: int = 200) -> str:
    clean = re.sub(r'[^a-zA-Z0-9/_\-.]', '_', str(value))
    return clean[:max_len]

# ── Métricas de riesgo (Optimizadas para PHP Nativo) ─────────────────────────
def calculate_risk_metrics(diff: str) -> dict:
    lines = diff.split("\n")
    metrics = {
        "lines_added":        len([l for l in lines if l.startswith("+") and not l.startswith("+++")]),
        "lines_removed":      len([l for l in lines if l.startswith("-") and not l.startswith("---")]),
        "files_changed":      len(set(re.findall(r'diff --git a/(.*?) b/', diff))),
        "has_auth_changes":   bool(re.search(r'(auth|login|password|session|cookie)', diff, re.I)),
        "has_db_changes":      bool(re.search(r'(mysqli|pdo|query|select|insert|union)', diff, re.I)),
        # Detección de funciones peligrosas comunes en PHP base
        "has_dangerous_funcs": bool(re.search(r'(eval|exec|shell_exec|system|passthru|base64_decode|gzuncompress)', diff, re.I)),
        "has_file_inclusion": bool(re.search(r'(include|require)(_once)?\s*\$_(GET|POST|REQUEST)', diff, re.I)),
    }

    score = 0
    score += min(metrics["lines_added"] // 15, 5)
    score += 5 if metrics["has_dangerous_funcs"] else 0
    score += 5 if metrics["has_file_inclusion"] else 0
    score += 4 if metrics["has_auth_changes"]    else 0
    score += 3 if metrics["has_db_changes"]      else 0

    metrics["risk_score"] = score
    if score >= 12: metrics["risk_level"] = "CRITICAL"
    elif score >= 8: metrics["risk_level"] = "HIGH"
    elif score >= 4: metrics["risk_level"] = "MEDIUM"
    else: metrics["risk_level"] = "LOW"

    return metrics

# ── Llamada a Groq API ────────────────────────────────────────────────────────
def call_groq_api(api_key: str, diff: str, metrics: dict, timeout: int = 30) -> Optional[str]:
    system_prompt = (
        "Eres un Auditor Senior de Ciberseguridad. Especialista en PHP nativo y OWASP. "
        "Tu tarea es encontrar fallos de seguridad (SQLi, XSS, RCE, LFI) en el diff proporcionado. "
        "Responde en Markdown claro y directo."
    )

    user_prompt = f"""Analiza este código PHP:
**RIESGO CALCULADO:** {metrics["risk_level"]} ({metrics["risk_score"]}/20)

**DIFF:**
```diff
{diff}