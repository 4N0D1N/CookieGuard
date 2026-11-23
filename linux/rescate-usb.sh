#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTNAME=$(hostname 2>/dev/null || echo "host")
TIMESTAMP=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "sesion")
RESCUE_DIR="${SCRIPT_DIR}/Informes_Rescate_${HOSTNAME}_${TIMESTAMP}"
mkdir -p "$RESCUE_DIR"

export COOKIEGUARD_HOME="$RESCUE_DIR"

echo "======================================================================"
echo "  🚨 COOKIEGUARD - PROTOCOLO DE RESCATE Y TRIAGE FORENSE USB 🚨"
echo "======================================================================"
echo "Ejecutando desde: $SCRIPT_DIR"
echo "Destino del informe de rescate: $RESCUE_DIR"
echo ""

if [ -f "${SCRIPT_DIR}/CookieGuard" ]; then
    echo "[OK] Ejecutando binario standalone CookieGuard..."
    "${SCRIPT_DIR}/CookieGuard" triage --salida "$RESCUE_DIR"
else
    echo "[INFO] Ejecutando mediante Python..."
    python3 -m cookieguard triage --salida "$RESCUE_DIR"
fi

echo ""
echo "======================================================================"
echo "Rescate completado."
echo "Archivos generados en: $RESCUE_DIR"
echo "  * Informe interactivo: $RESCUE_DIR/Informe_Rescate.html"
echo "  * Checklist urgente:   $RESCUE_DIR/URGENTE_ROTAR_CLAVES.txt"
echo "======================================================================"
