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
BLUE="\033[34m"
MAGENTA="\033[35m"

echo ""
echo -e "${BOLD}${CYAN}▲ TeamVault — Gestión de entorno${RESET}"
echo -e "${GRAY}─────────────────────────────────────${RESET}"
echo ""

# ── Elegir modo ───────────────────────────────────────────────────────────────
echo -e "${BOLD}¿Qué quieres hacer?${RESET}"
echo ""
echo -e "  ${CYAN}1${RESET}  🖥️  Arrancar en LOCAL (npm run dev)"
echo -e "  ${CYAN}2${RESET}  ▲  Publicar en PRODUCCIÓN (GitHub → Vercel)"
echo ""
read -p "Elige [1/2]: " MODE
echo ""

# ══ MODO LOCAL ════════════════════════════════════════════════════════════════
if [ "$MODE" = "1" ]; then
  echo -e "${BOLD}${BLUE}🖥️  Modo LOCAL${RESET}"
  echo -e "${GRAY}─────────────────────────────────────${RESET}"

  # Verificar que existe package.json
  if [ ! -f "package.json" ]; then
    echo -e "${RED}✗ No se encuentra package.json${RESET}"
    echo -e "${GRAY}Asegúrate de ejecutar el script desde la raíz del proyecto${RESET}"
    exit 1
  fi

  # Verificar que existe .env.local
  if [ ! -f ".env.local" ]; then
    echo -e "${YELLOW}⚠ No se encuentra .env.local${RESET}"
    echo -e "${GRAY}Creando .env.local vacío — rellena las variables de Supabase${RESET}"
    cat > .env.local << 'EOF'
NEXT_PUBLIC_SUPABASE_URL=https://xxxxxxxxxxxx.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
EOF
    echo -e "${YELLOW}⚠ Edita .env.local con tus valores reales antes de continuar${RESET}"
    exit 1
  fi

  # Verificar node_modules
  if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}⚠ node_modules no existe. Instalando dependencias...${RESET}"
    npm install
    if [ $? -ne 0 ]; then
      echo -e "${RED}✗ Error en npm install${RESET}"
      exit 1
    fi
  fi

  echo -e "${GREEN}✓${RESET} Entorno verificado"
  echo ""
  echo -e "${BOLD}Arrancando servidor de desarrollo...${RESET}"
  echo -e "${GRAY}URL: http://localhost:3000${RESET}"
  echo -e "${GRAY}Pulsa Ctrl+C para detener${RESET}"
  echo ""
  npm run dev
  exit 0
fi

# ══ MODO PRODUCCIÓN ═══════════════════════════════════════════════════════════
if [ "$MODE" = "2" ]; then
  echo -e "${BOLD}${MAGENTA}▲ Modo PRODUCCIÓN${RESET}"
  echo -e "${GRAY}─────────────────────────────────────${RESET}"

  # Verificar que estamos en un repo git
  if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED}✗ No estás dentro de un repositorio git${RESET}"
    exit 1
  fi

  # Verificar rama actual
  BRANCH=$(git branch --show-current)
  echo -e "${GRAY}Rama actual: ${BOLD}${BRANCH}${RESET}"

  # Mensaje del commit
  if [ -n "$1" ]; then
    MSG="$1"
  else
    echo ""
    read -p "Mensaje del commit (Enter para fecha automática): " MSG
    if [ -z "$MSG" ]; then
      MSG="Update $(date '+%Y-%m-%d %H:%M')"
    fi
  fi

  echo ""

  # Verificar si hay cambios
  if git diff --quiet && git diff --cached --quiet; then
    if [ -z "$(git ls-files --others --exclude-standard)" ]; then
      echo -e "${YELLOW}⚠ No hay cambios que publicar${RESET}"
      echo -e "${GRAY}El código en GitHub ya está actualizado${RESET}"
      echo ""
      exit 0
    fi
  fi

  # Mostrar archivos modificados
  echo -e "${BOLD}Archivos que se van a publicar:${RESET}"
  git status --short
  echo ""
  echo -e "${BOLD}Mensaje:${RESET} ${MSG}"
  echo ""

  # Advertencia sobre .env.local
  echo -e "${YELLOW}⚠ Recuerda: .env.local NO se sube a GitHub${RESET}"
  echo -e "${GRAY}  Si cambiaste variables de entorno, actualízalas en${RESET}"
  echo -e "${GRAY}  Vercel → Settings → Environment Variables${RESET}"
  echo ""

  read -p "¿Continuar con el deploy? (Enter = sí / Ctrl+C = cancelar) " confirm
  echo ""

  # Git add
  echo -e "${CYAN}[1/3]${RESET} Añadiendo archivos..."
  git add .
  if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Error en git add${RESET}"
    exit 1
  fi
  echo -e "${GREEN}✓${RESET} Archivos añadidos"

  # Git commit
  echo -e "${CYAN}[2/3]${RESET} Creando commit..."
  git commit -m "$MSG"
  if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Error en git commit${RESET}"
    exit 1
  fi
  echo -e "${GREEN}✓${RESET} Commit creado"

  # Git push
  echo -e "${CYAN}[3/3]${RESET} Subiendo a GitHub..."
  git push
  if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Error en git push${RESET}"
    echo -e "${GRAY}Comprueba tu conexión o el token de GitHub${RESET}"
    exit 1
  fi
  echo -e "${GREEN}✓${RESET} Subido a GitHub"

  # Éxito
  echo ""
  echo -e "${GRAY}─────────────────────────────────────${RESET}"
  echo -e "${GREEN}${BOLD}✓ Deploy completado${RESET}"
  echo -e "${GRAY}Vercel desplegará los cambios en ~2 minutos${RESET}"
  echo -e "${GRAY}Progreso: vercel.com/dashboard${RESET}"
  echo ""
  exit 0
fi

# ── Opción no válida ──────────────────────────────────────────────────────────
echo -e "${RED}✗ Opción no válida. Elige 1 o 2${RESET}"
echo ""
exit 1