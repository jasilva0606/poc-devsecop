package main

# ─────────────────────────────────────────────────────────────────────────────
# OPA Conftest — Políticas de seguridad para Dockerfile
#
# Uso: conftest test Dockerfile --policy .github/policies/
#
# Estructura de input para Dockerfiles (conftest parser):
#   input[i].Cmd   = instrucción en minúsculas ("from", "run", "user", "env", ...)
#   input[i].Value = array de strings con los argumentos
#   input[i].SubCmd = sub-instrucción cuando aplica (ej. HEALTHCHECK)
# ─────────────────────────────────────────────────────────────────────────────

# ── CRITICAL: No ejecutar como root ──────────────────────────────────────────
deny[msg] {
input[i].Cmd == "user"
user := input[i].Value[0]
lower(user) == "root"
msg := "CRITICAL [CIS-DI-0006]: El contenedor no debe ejecutarse como root. Usar USER www-data o un UID no-root."
}

# Detectar ausencia total de instrucción USER (corre como root por defecto)
deny[msg] {
not any_user_instruction
msg := "CRITICAL [CIS-DI-0006]: No se encontró instrucción USER. El contenedor corre como root por defecto. Agregar: USER www-data"
}

any_user_instruction {
input[i].Cmd == "user"
}

# ── CRITICAL: No usar :latest como tag de imagen base ────────────────────────
deny[msg] {
input[i].Cmd == "from"
image := input[i].Value[0]
endswith(image, ":latest")
msg := sprintf("CRITICAL [CIS-DI-0001]: Imagen base usa ':latest' (%s). Especificar un tag inmutable para builds reproducibles.", [image])
}

# ── HIGH: No exponer puertos privilegiados (< 1024) ──────────────────────────
deny[msg] {
input[i].Cmd == "expose"
port := to_number(input[i].Value[0])
port < 1024
msg := sprintf("HIGH [CIS-DI-0005]: Puerto privilegiado expuesto (%d). Los puertos < 1024 requieren root. Usar puertos >= 1024.", [port])
}

# ── HIGH: No hardcodear secrets en instrucciones ENV ─────────────────────────
deny[msg] {
input[i].Cmd == "env"
env_pair := input[i].Value[_]
secret_patterns := ["password", "passwd", "secret", "api_key", "apikey", "token", "private_key", "auth"]
pattern := secret_patterns[_]
contains(lower(env_pair), pattern)
msg := sprintf("HIGH [CWE-798]: Posible secret hardcodeado en ENV: '%s'. Usar secrets del runtime (Docker secrets, env vars del runner).", [env_pair])
}

# ── HIGH: No usar ADD cuando COPY es suficiente ──────────────────────────────
deny[msg] {
input[i].Cmd == "add"
source := input[i].Value[0]
not startswith(source, "http://")
not startswith(source, "https://")
not endswith(source, ".tar.gz")
not endswith(source, ".tar.bz2")
not endswith(source, ".tar.xz")
msg := "MEDIUM [CIS-DI-0009]: Usar COPY en lugar de ADD para copiar archivos locales. ADD tiene comportamiento implícito (descompresión, descarga) que puede ser inesperado."
}

# ── MEDIUM: HEALTHCHECK obligatorio ──────────────────────────────────────────
deny[msg] {
not any_healthcheck
msg := "MEDIUM [CIS-DI-0011]: No se encontró instrucción HEALTHCHECK. Sin healthcheck, el orquestador no puede detectar contenedores en estado degradado."
}

any_healthcheck {
input[i].Cmd == "healthcheck"
}

# ── MEDIUM: No instalar herramientas de debug en imagen de producción ─────────
warn[msg] {
input[i].Cmd == "run"
cmd := concat(" ", input[i].Value)
debug_tools := ["curl", "wget", "netcat", "nc", "nmap", "tcpdump", "strace", "gdb", "vim", "nano"]
tool := debug_tools[_]
contains(lower(cmd), tool)
msg := sprintf("MEDIUM: Herramienta de diagnóstico instalada en imagen: '%s'. Considerar eliminarla de la imagen de producción o usar multi-stage build.", [tool])
}

# ── MEDIUM: apk/apt con --no-cache para reducir superficie de ataque ─────────
warn[msg] {
input[i].Cmd == "run"
cmd := concat(" ", input[i].Value)
contains(cmd, "apk add")
not contains(cmd, "--no-cache")
msg := "MEDIUM: 'apk add' sin '--no-cache'. Usar 'apk add --no-cache' para no dejar el índice de paquetes en la imagen final."
}

warn[msg] {
input[i].Cmd == "run"
cmd := concat(" ", input[i].Value)
contains(cmd, "apt-get install")
not contains(cmd, "rm -rf /var/lib/apt/lists")
msg := "MEDIUM: 'apt-get install' sin limpiar listas. Agregar 'rm -rf /var/lib/apt/lists/*' al final del RUN para reducir tamaño."
}

# ── LOW: WORKDIR debe ser absoluto ────────────────────────────────────────────
deny[msg] {
input[i].Cmd == "workdir"
dir := input[i].Value[0]
not startswith(dir, "/")
msg := sprintf("LOW: WORKDIR relativo detectado: '%s'. WORKDIR debe ser una ruta absoluta.", [dir])
}

# ── LOW: LABEL maintainer debe estar presente ─────────────────────────────────
warn[msg] {
not any_maintainer_label
msg := "LOW: No se encontró LABEL maintainer. Agregar metadatos de contacto facilita la gestión operativa."
}

any_maintainer_label {
input[i].Cmd == "label"
pair := input[i].Value[_]
contains(lower(pair), "maintainer")
}