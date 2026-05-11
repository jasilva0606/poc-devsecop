# 🛡️ DevSecOps Pipeline — Enterprise Grade

Pipeline de seguridad completo para aplicaciones PHP, construido sobre GitHub Actions con 10 fases de cobertura, supply chain protection y AI-assisted audit.

**Mantenido por**: Jorge Silva · **Versión**: 2.1.0 · **Última actualización**: Mayo 2026

---

## 📊 Security Score: 90/100

| Categoría | Score | Herramientas |
|---|---|---|
| 🔐 Secret Scanning | ✅ 10/10 | Gitleaks v2.3.9 + TruffleHog v3.94.3 |
| 📦 SCA (Dependencias) | ✅ 10/10 | Snyk CLI v1.1296.2 (SHA256 verificado) |
| 🔬 SAST | ✅ 10/10 | PHPStan nivel 8 + Semgrep OWASP |
| 🏗️ IaC Security | ✅ 10/10 | Checkov v12.3075.0 |
| 🐳 Container Security | ✅ 10/10 | Trivy v0.36.0 (post-incidente supply chain) |
| 🎯 DAST | ✅ 10/10 | StackHawk v2.2.0 con stack nginx+fpm |
| 📜 SBOM | ✅ 10/10 | Syft (SPDX-JSON + CycloneDX) |
| 🤖 AI Audit | ✅ 10/10 | Groq LLaMA 3.3 70B con sanitización |
| 📊 Reporting | ✅ 10/10 | Security scorecard + audit log con jq |
| 🔗 Supply Chain | ✅ 10/10 | Todas las actions fijadas a SHA verificados |
| ⚖️ License Compliance | ⚠️ 5/10 | Pendiente — ver roadmap |
| 🛡️ Policy as Code | ⚠️ 5/10 | Pendiente — ver roadmap |

**Score total: 90/100** — Productivo. Sin hallazgos críticos ni de alta severidad.

---

## ⚠️ Incidente de supply chain — Trivy (Marzo 2026)

`aquasecurity/trivy-action` fue comprometido: 75 de 76 tags fueron reemplazados por un infostealer que robaba secrets de CI/CD. Este pipeline usa `v0.36.0` (`a9c7b0f0`), el primer release post-incidente verificado por Aqua Security.

**Nunca usar** `@master`, `@main`, ni ningún tag anterior a `v0.35.0`.

---

## 🏗️ Arquitectura del pipeline

```
PUSH / PR / SCHEDULE
        │
        ▼
┌───────────────────┐
│  PREFLIGHT        │  Valida secrets obligatorios antes de gastar runner
│  GITLEAKS_LICENSE │  Fallo rápido si falta SNYK_TOKEN o GITLEAKS_LICENSE
│  SNYK_TOKEN       │
└────────┬──────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  FASE 1 — SECRET SCANNING                           │
│  Gitleaks (historial completo) + TruffleHog         │
│  Ambos bloqueantes — sin continue-on-error          │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  FASE 2 — SCA (Software Composition Analysis)       │
│  Snyk CLI con verificación SHA256 antes de ejecutar │
│  Gate duro: exit 1 = vulnerabilidades HIGH/CRITICAL │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  FASE 3 — SAST (Static Analysis)                   │
│  PHPStan nivel 8 + Semgrep (auto + owasp + php)    │
│  Ambos bloqueantes                                  │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  FASE 4 — IaC SECURITY                              │
│  Checkov: Dockerfile + GitHub Actions               │
│  soft_fail: false — gate duro                       │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  FASE 5 — CONTAINER BUILD & SCAN                    │
│  docker build --no-cache                            │
│  Trivy: exit-code 1 si CRITICAL/HIGH                │
│  SARIF → GitHub Security tab                        │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  FASE 6 — DAST (Dynamic Testing)                    │
│  Stack: nginx:alpine → FastCGI → php-fpm            │
│  StackHawk escanea HTTP real en localhost:8080      │
│  Solo en push (no en PRs)                           │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  FASE 7 — SBOM                                      │
│  Syft genera SPDX-JSON + CycloneDX                  │
│  Solo en push a main — retención 7 días             │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  FASE 8 — AI SECURITY AUDIT                         │
│  Groq LLaMA 3.3 70B analiza el diff del PR          │
│  Sanitización de secrets + límite de diff 200KB     │
│  Solo en pull_request                               │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  FASE 9 — SECURITY SCORE & SUMMARY                  │
│  Score ponderado: Gitleaks 25 + TruffleHog 25 +     │
│  Snyk 15 + PHPStan 15 + Semgrep 10 +                │
│  Trivy 20 + Checkov 10                              │
└────────┬────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│  FASE 10 — AUDIT LOGGING                            │
│  JSON generado con jq (seguro contra inyección)     │
│  Retención: 7 días (límite del repo)                │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 Setup

### 1. Secrets obligatorios

En GitHub: **Settings → Secrets and variables → Actions**

| Secret | Descripción | Obtener en |
|---|---|---|
| `GITLEAKS_LICENSE` | Licencia Gitleaks (enterprise) | [gitleaks.io](https://gitleaks.io) |
| `SNYK_TOKEN` | Token de Snyk | [app.snyk.io](https://app.snyk.io/account) |

### 2. Secrets opcionales (habilitan fases adicionales)

| Secret | Fase que habilita | Obtener en |
|---|---|---|
| `GROQ_API_KEY` | Fase 8 — AI Audit | [console.groq.com](https://console.groq.com) |
| `HAWK_TOKEN` | Fase 6 — DAST | [app.stackhawk.com](https://app.stackhawk.com) |
| `HAWK_APP_ID` | Fase 6 — DAST | Portal StackHawk |

### 3. Estructura de archivos requerida

```
.
├── .github/
│   ├── workflows/
│   │   └── devsecops.yml          # Pipeline principal
│   ├── scripts/
│   │   ├── ai_audit.py            # AI audit con Groq
│   │   └── update-action-pins.sh  # Actualización mensual de SHAs
│   └── policies/
│       └── dockerfile.rego        # (roadmap) OPA Conftest policies
├── .dockerignore                  # Excluye .git, tests, .github de la imagen
├── .stackhawk.yml                 # Placeholder — se genera en runtime
├── Dockerfile                     # Multi-stage, usuario non-root, healthcheck
└── composer.json
```

### 4. Activar DAST (StackHawk)

El DAST se omite silenciosamente si `HAWK_TOKEN` o `HAWK_APP_ID` no están configurados. Para activarlo:

1. Crear cuenta en [app.stackhawk.com](https://app.stackhawk.com)
2. Crear una aplicación y copiar el App ID
3. Configurar `HAWK_TOKEN` y `HAWK_APP_ID` en GitHub Secrets

### 5. Activar AI Audit (Groq — gratuito)

1. Crear cuenta en [console.groq.com](https://console.groq.com)
2. Ir a **API Keys** → crear nueva key (`gsk_...`)
3. Configurar `GROQ_API_KEY` en GitHub Secrets

Límites del tier gratuito: 30 req/min · 14,400 req/día · suficiente para CI/CD.

---

## 🔒 Supply chain security — SHA pinning

Todas las GitHub Actions están fijadas a SHAs de commit verificados con `gh api`. Esto previene ataques de supply chain donde un actor malicioso modifica un tag existente.

| Action | Versión | SHA verificado |
|---|---|---|
| `actions/checkout` | v4.2.2 | `11bd71901bbe5b1630ceea73d27597364c9af683` |
| `actions/upload-artifact` | v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `github/codeql-action` | codeql-bundle-v2.21.4 | `bc02a25f6449997c5e9d5a368879b28f56ae19a1` |
| `gitleaks/gitleaks-action` | v2.3.9 | `ff98106e4c7b2bc287b24eaf42907196329070c7` |
| `trufflesecurity/trufflehog` | v3.94.3 | `47e7b7cd74f578e1e3145d48f669f22fd1330ca6` |
| `aquasecurity/trivy-action` | v0.36.0 ⚠️ | `a9c7b0f06e461e9d4b4d1711f154ee024b8d7ab8` |
| `bridgecrewio/checkov-action` | v12.3075.0 | `02a4c5d6a02367e5ea493c34c26b094302fd3f61` |
| `stackhawk/hawkscan-action` | v2.2.0 | `29a62fe1e926ea50ac87a1b64efc59b82ffd5b7d` |
| `shivammathur/setup-php` | @v2 | Rolling tag (intencional — ver [docs](https://github.com/shivammathur/setup-php#usage)) |

**Actualización mensual de SHAs:**

```bash
chmod +x .github/scripts/update-action-pins.sh
./.github/scripts/update-action-pins.sh
# Revisar el diff generado y hacer commit
```

---

## 🗺️ Roadmap — Para llegar al 100/100

Los siguientes ítems son los pendientes que llevarían el score de 90 a 100:

### ⚖️ License Compliance (falta 5 pts)

Verificar automáticamente que ninguna dependencia tiene licencia GPL, AGPL o propietaria que sea incompatible con el proyecto.

```yaml
- name: ⚖️ License Compliance Check
  run: |
    composer require --dev dominikb/composer-license-checker --no-interaction
    vendor/bin/composer-license-checker check \
      --allowList MIT \
      --allowList Apache-2.0 \
      --allowList BSD-2-Clause \
      --allowList BSD-3-Clause \
      --allowList ISC
```

### 🛡️ Policy as Code con OPA Conftest (falta 5 pts)

Validar el Dockerfile contra políticas Rego customizadas, más expresivas que Checkov solo.

```bash
# Crear .github/policies/dockerfile.rego
# Instalar conftest en el workflow:
curl -L https://github.com/open-policy-agent/conftest/releases/download/v0.56.0/conftest_Linux_x86_64.tar.gz \
  | tar xz && sudo mv conftest /usr/local/bin/
conftest test Dockerfile --policy .github/policies/
```

Ejemplo de política en `dockerfile.rego`:

```rego
package main

deny[msg] {
  input[i].Cmd == "user"
  input[i].Value[0] == "root"
  msg = "No ejecutar el contenedor como root"
}

deny[msg] {
  input[i].Cmd == "from"
  endswith(input[i].Value[0], ":latest")
  msg = "No usar :latest como tag de imagen base"
}
```

### 🔄 Mantenimiento recurrente (no suma pts, pero es crítico)

```bash
# Ejecutar mensualmente:
./.github/scripts/update-action-pins.sh

# Actualizar Snyk CLI en el workflow cuando salga nueva versión:
# SNYK_VERSION="v1.XXXX.X"  ← verificar en https://github.com/snyk/cli/releases
```

---

## 🐳 Dockerfile — Decisiones de seguridad

El Dockerfile implementa multi-stage build con las siguientes consideraciones:

- **Stage 1 (builder)**: instala git, unzip y composer solo para resolver dependencias. No llega a producción.
- **Stage 2 (runtime)**: imagen `php:8.3-fpm-alpine` mínima. Solo `libzip` y `fcgi` (para healthcheck).
- **Usuario non-root**: `USER www-data` — el proceso PHP-FPM no tiene privilegios de sistema.
- **Healthcheck real**: usa `cgi-fcgi` para validar que PHP-FPM responde el protocolo FastCGI, no solo que el proceso existe.
- **`.dockerignore`**: excluye `.git`, `.github/`, `tests/`, `*.sarif`, `*.md` — la imagen de producción no contiene artefactos de desarrollo ni historial de git.

> **Nota sobre DAST**: php-fpm expone FastCGI (puerto 9000), no HTTP. El step de DAST levanta un `nginx:alpine` como proxy HTTP→FastCGI para que StackHawk pueda hacer requests HTTP reales.

---

## 🔧 Troubleshooting

### "GITLEAKS_LICENSE / SNYK_TOKEN no encontrado"

El job `preflight` falla rápido si estos secrets no están configurados.

```bash
gh secret list                          # verificar qué secrets existen
gh secret set GITLEAKS_LICENSE          # configurar interactivamente
gh secret set SNYK_TOKEN
```

### "sha256sum: snyk-linux: No such file or directory"

El archivo `.sha256` de Snyk referencia el nombre original `snyk-linux`. Descargar conservando ese nombre:

```bash
# Correcto:
curl -sSL ".../snyk-linux" -o snyk-linux
curl -sSL ".../snyk-linux.sha256" -o snyk-linux.sha256
sha256sum -c snyk-linux.sha256           # busca "snyk-linux", lo encuentra
```

### "Unable to resolve action @SHA"

Los SHAs en el workflow fueron verificados con `gh api` el 2026-05-10. Si un SHA falla es porque fue verificado incorrectamente. Obtener el SHA real:

```bash
gh api repos/{owner}/{repo}/git/ref/tags/{tag} --jq '.object.sha'
# Ejemplo:
gh api repos/aquasecurity/trivy-action/git/ref/tags/v0.36.0 --jq '.object.sha'
```

### "StackHawk: applicationId: '' — Invalid value"

StackHawk CLI no interpola `${VAR}` en el YAML. El archivo `.stackhawk.yml` se genera en runtime en el step `Generate StackHawk config` con el valor real de `HAWK_APP_ID`. Verificar que el secret está configurado.

### "Trivy Container Scan — exit code 1"

Trivy encontró CVEs de severidad CRITICAL o HIGH en la imagen. Ver el reporte:

```bash
gh run download <run-id>                # descarga artifacts incluyendo trivy-results.sarif
# O en GitHub: Security tab → Code scanning alerts
```

Para actualizar la imagen base si la vulnerabilidad está en el OS:

```dockerfile
FROM php:8.3-fpm-alpine  # actualizar al tag más reciente disponible
```

### "Semgrep — chmod: Operation not permitted"

El container de Semgrep corre como root y crea `semgrep.sarif` con permisos que el runner no puede cambiar. El `chmod` fue removido del workflow — el archivo es legible por `codeql-action/upload-sarif` sin necesitar el cambio de permisos.

### "Retention days cannot be greater than the maximum allowed"

El repo tiene configurado un máximo de 7 días en **Settings → Actions → General → Artifact and log retention**. Para subir el límite: Settings → Actions → General → Artifact and log retention → cambiar a 90 o 365 días.

---

## 📋 Compliance

Este pipeline genera evidencia técnica para los siguientes estándares:

| Estándar | Control cubierto | Evidencia generada |
|---|---|---|
| **OWASP Top 10 (2021)** | A06 Vulnerable Components, A05 Security Misconfiguration | Snyk + Trivy SARIFs |
| **NIST CSF** | ID.RA (Risk Assessment), PR.DS (Data Security) | Audit log JSON |
| **ISO 27001** | A.14.2.2 (System change control) | Pipeline run artifacts |
| **SOC 2 Type II** | CC7.1 (System monitoring) | Security scorecard |
| **CIS Benchmarks** | Docker CIS | Checkov SARIF |

---

## 📚 Referencias técnicas

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [GitHub Actions — SHA pinning](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)
- [Trivy supply chain incident (Marzo 2026)](https://github.com/aquasecurity/trivy/discussions/10425)
- [StackHawk — FastCGI apps](https://docs.stackhawk.com/hawkscan/configuration)
- [Snyk CLI reference](https://docs.snyk.io/snyk-cli/cli-commands-and-options-summary)
- [Semgrep rules — PHP](https://semgrep.dev/p/php)

---

## 🤝 Contribuciones

1. Fork el repositorio
2. Crear feature branch: `git checkout -b feat/nueva-herramienta`
3. Commit con conventional commits: `git commit -m 'feat: add grype as secondary container scanner'`
4. Push: `git push origin feat/nueva-herramienta`
5. Abrir Pull Request → el AI Audit analizará el diff automáticamente

---

## 📄 License

MIT License — ver archivo `LICENSE`