#!/usr/bin/env bash
# .github/scripts/update-action-pins.sh
#
# Utilitario para actualizar los SHAs de las GitHub Actions pinneadas.
# Ejecutar manualmente o en un workflow de mantenimiento mensual.
#
# Requisitos: gh CLI autenticado, jq
#
# Uso:
#   chmod +x .github/scripts/update-action-pins.sh
#   ./.github/scripts/update-action-pins.sh
#   # Revisar el diff generado y hacer commit

set -euo pipefail

WORKFLOW_FILE=".github/workflows/devsecops.yml"

if [ ! -f "$WORKFLOW_FILE" ]; then
  echo "❌ No se encontró $WORKFLOW_FILE"
  exit 1
fi

if ! command -v gh &>/dev/null; then
  echo "❌ gh CLI no está instalado. Ver: https://cli.github.com"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo "❌ jq no está instalado."
  exit 1
fi

echo "🔍 Actualizando SHAs de GitHub Actions en $WORKFLOW_FILE"
echo ""

# Lista de actions a verificar: "owner/repo:tag_or_branch"
declare -a ACTIONS=(
  "actions/checkout:v4"
  "actions/upload-artifact:v4"
  "github/codeql-action:v3"
  "shivammathur/setup-php:v2"
  "gitleaks/gitleaks-action:v2"
  "trufflesecurity/trufflehog:v3"
  "snyk/actions:v0"
  "bridgecrewio/checkov-action:master"
  "aquasecurity/trivy-action:master"
  "stackhawk/hawkscan-action:v2"
)

for action_ref in "${ACTIONS[@]}"; do
  owner_repo="${action_ref%%:*}"
  tag="${action_ref##*:}"

  echo "  📌 $owner_repo @ $tag"

  # Obtener SHA del tag/branch via API de GitHub
  sha=$(gh api "repos/$owner_repo/git/ref/tags/$tag" --jq '.object.sha' 2>/dev/null \
    || gh api "repos/$owner_repo/git/ref/heads/$tag" --jq '.object.sha' 2>/dev/null \
    || echo "")

  # Si el ref apunta a un tag object (annotated tag), resolver al commit
  if [ -n "$sha" ]; then
    obj_type=$(gh api "repos/$owner_repo/git/tags/$sha" --jq '.object.type' 2>/dev/null || echo "")
    if [ "$obj_type" = "commit" ]; then
      sha=$(gh api "repos/$owner_repo/git/tags/$sha" --jq '.object.sha' 2>/dev/null || echo "$sha")
    fi
  fi

  if [ -z "$sha" ]; then
    echo "    ⚠️  No se pudo obtener SHA para $owner_repo:$tag — saltando"
    continue
  fi

  echo "    SHA: $sha"

  # Reemplazar en el archivo de workflow
  # Busca patrones como: uses: owner/repo/subdir@SHA o uses: owner/repo@SHA
  # con comentario de version opcionalmente
  sed -i.bak \
    "s|uses: ${owner_repo}[^@]*@[a-f0-9]\{40\}|uses: ${owner_repo}@${sha}|g" \
    "$WORKFLOW_FILE"

done

# Limpiar backups de sed
rm -f "${WORKFLOW_FILE}.bak"

echo ""
echo "✅ SHAs actualizados. Revisar el diff:"
echo ""
git diff "$WORKFLOW_FILE" 2>/dev/null || diff /dev/null /dev/null

echo ""
echo "📝 Próximos pasos:"
echo "   1. Revisar los cambios con: git diff $WORKFLOW_FILE"
echo "   2. Hacer commit: git add $WORKFLOW_FILE && git commit -m 'chore: update action pins'"
echo "   3. Abrir PR para revisión"
