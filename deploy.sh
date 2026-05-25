#!/bin/bash

# ── TeamVault Deploy Script ───────────────────────────────────────────────────
# Uso: ./deploy.sh "descripción del cambio"
#      ./deploy.sh              (usa mensaje automático con fecha y hora)

RESET="\033[0m"
BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
RED="\033[31m"
GRAY="\033[90m"

echo ""
echo -e "${BOLD}${CYAN}▲ TeamVault Deploy${RESET}"
echo -e "${GRAY}─────────────────────────────────────${RESET}"

# ── Verificar que estamos en un repo git ──────────────────────────────────────
if ! git rev-parse --git-dir > /dev/null 2>&1; then
  echo -e "${RED}✗ No estás dentro de un repositorio git${RESET}"
  exit 1
fi

# ── Mensaje del commit ────────────────────────────────────────────────────────
if [ -n "$1" ]; then
  MSG="$1"
else
  MSG="Update $(date '+%Y-%m-%d %H:%M')"
fi

# ── Verificar si hay cambios ──────────────────────────────────────────────────
if git diff --quiet && git diff --cached --quiet; then
  # Comprobar archivos sin seguimiento
  if [ -z "$(git ls-files --others --exclude-standard)" ]; then
    echo -e "${YELLOW}⚠ No hay cambios que publicar${RESET}"
    echo ""
    exit 0
  fi
fi

# ── Mostrar archivos que se van a subir ───────────────────────────────────────
echo -e "${BOLD}Archivos modificados:${RESET}"
git status --short
echo ""

# ── Confirmar ─────────────────────────────────────────────────────────────────
echo -e "${BOLD}Mensaje del commit:${RESET} ${MSG}"
echo ""
read -p "¿Continuar? (Enter para sí / Ctrl+C para cancelar) " confirm
echo ""

# ── Git add ───────────────────────────────────────────────────────────────────
echo -e "${CYAN}[1/3]${RESET} Añadiendo archivos..."
git add .
if [ $? -ne 0 ]; then
  echo -e "${RED}✗ Error en git add${RESET}"
  exit 1
fi
echo -e "${GREEN}✓${RESET} git add completado"

# ── Git commit ────────────────────────────────────────────────────────────────
echo -e "${CYAN}[2/3]${RESET} Creando commit..."
git commit -m "$MSG"
if [ $? -ne 0 ]; then
  echo -e "${RED}✗ Error en git commit${RESET}"
  exit 1
fi
echo -e "${GREEN}✓${RESET} Commit creado"

# ── Git push ──────────────────────────────────────────────────────────────────
echo -e "${CYAN}[3/3]${RESET} Subiendo a GitHub..."
git push
if [ $? -ne 0 ]; then
  echo -e "${RED}✗ Error en git push${RESET}"
  echo -e "${GRAY}Comprueba tu conexión o el token de GitHub${RESET}"
  exit 1
fi

# ── Éxito ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GRAY}─────────────────────────────────────${RESET}"
echo -e "${GREEN}${BOLD}✓ Publicado correctamente${RESET}"
echo -e "${GRAY}Vercel desplegará los cambios en ~2 minutos${RESET}"
echo -e "${GRAY}Puedes seguir el progreso en vercel.com/dashboard${RESET}"
echo ""
