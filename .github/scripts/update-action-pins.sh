#!/usr/bin/env bash
# .github/scripts/update-action-pins.sh

set -euo pipefail

WORKFLOW_FILE=".github/workflows/devsecops.yml"

# Validaciones iniciales
if [ ! -f "$WORKFLOW_FILE" ]; then
  echo "❌ No se encontró $WORKFLOW_FILE"
  exit 1
fi

if ! command -v gh &>/dev/null; then
  echo "❌ gh CLI no está instalado."
  exit 1
fi

echo "🔍 Actualizando SHAs de GitHub Actions en $WORKFLOW_FILE"

# Lista de actions: "owner/repo:tag"
# Nota: Para acciones con subdirectorios (como snyk/actions/php), 
# se define el repo base y el script resuelve el SHA del commit raíz.
declare -a ACTIONS=(
  "actions/checkout:v4"
  "actions/upload-artifact:v4"
  "github/codeql-action:v3"
  "shivammathur/setup-php:v2"
  "gitleaks/gitleaks-action:v2"
  "trufflesecurity/trufflehog:v3"
  "snyk/actions:v0"
  "bridgecrewio/checkov-action:main"
  "aquasecurity/trivy-action:main"
  "stackhawk/hawkscan-action:v2"
)

for action_ref in "${ACTIONS[@]}"; do
  owner_repo="${action_ref%%:*}"
  tag="${action_ref##*:}"

  echo "  📌 Buscando SHA para $owner_repo @ $tag..."

  # 1. Intentar obtener el SHA del commit directamente (funciona para branches y tags)
  # Usamos 'rev-parse' via API para obtener el commit final real
  sha=$(gh api "repos/$owner_repo/commits/$tag" --jq '.sha' 2>/dev/null || echo "")

  if [ -z "$sha" ]; then
    echo "    ⚠️  No se pudo resolver $owner_repo:$tag — saltando"
    continue
  fi

  echo "    ✅ Commit SHA: $sha"

  # 2. Reemplazo con sed (Optimizado)
  # Esta regex busca 'uses: owner/repo' seguido de '@' y cualquier SHA de 40 caracteres,
  # respetando si hay subdirectorios como 'owner/repo/subdir@SHA'
  # El uso de [^ ]* permite capturar subdirectorios antes del @
  
  if [[ "$OSTYPE" == "darwin"* ]]; then
    # Versión para macOS (BSD sed)
    sed -i '' "s|\(uses: ${owner_repo}[^@]*\)@[a-f0-9]\{40\}|\1@${sha}|g" "$WORKFLOW_FILE"
  else
    # Versión para Linux (GNU sed)
    sed -i "s|\(uses: ${owner_repo}[^@]*\)@[a-f0-9]\{40\}|\1@${sha}|g" "$WORKFLOW_FILE"
  fi
done

echo ""
echo "✅ SHAs actualizados correctamente en $WORKFLOW_FILE"
echo "📝 Ejecuta 'git diff' para verificar los cambios."