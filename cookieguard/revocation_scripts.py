"""Genera guías seguras de revocación manual y plantillas no destructivas.

CookieGuard no puede revocar las sesiones cloud del usuario automáticamente sin
credenciales y APIs oficiales de cada proveedor. Las plantillas solo abren portales
oficiales; no eliminan tickets locales, no cierran navegadores y no vacían el portapapeles.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

from .common import data_dir, log

REVOCATION_URLS = [
    ("Google (Cerrar dispositivos y sesiones activas)", "https://myaccount.google.com/device-activity"),
    ("Microsoft / Outlook (Cerrar sesión en todas partes)", "https://account.live.com/proofs/manage/additional"),
    ("GitHub (Sesiones web y tokens SSH/OAuth)", "https://github.com/settings/sessions"),
    ("Amazon (Dispositivos registrados)", "https://www.amazon.es/ap/cnep"),
    ("PayPal (Dispositivos y permisos de seguridad)", "https://www.paypal.com/myaccount/security"),
    ("Apple ID (Dispositivos asociados)", "https://appleid.apple.com/account/manage"),
    ("Discord (Dispositivos conectados)", "https://discord.com/channels/@me"),
    ("Telegram Web (Sesiones activas)", "https://web.telegram.org"),
]


def generate_revocation_scripts(output_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Genera scripts para Windows (PowerShell), Linux (Bash) y guía corporativa."""
    target = Path(output_dir) if output_dir else data_dir() / "scripts_revocacion"
    target.mkdir(parents=True, exist_ok=True)

    ps1_path = target / "revoke_sessions_windows.ps1"
    sh_path = target / "revoke_sessions_linux.sh"
    guide_path = target / "guia_revocacion_corporativa.md"

    # 1. Script Windows PowerShell
    ps1_content = _build_powershell_script()
    with open(ps1_path, "w", encoding="utf-8") as f:
        f.write(ps1_content)

    # 2. Script Linux Bash
    sh_content = _build_bash_script()
    with open(sh_path, "w", encoding="utf-8") as f:
        f.write(sh_content)

    # 3. Guía corporativa Markdown
    guide_content = _build_corporate_guide()
    with open(guide_path, "w", encoding="utf-8") as f:
        f.write(guide_content)

    log(f"Scripts de revocación por lote generados en: {target}")

    return {
        "directorio": str(target),
        "windows_ps1": str(ps1_path),
        "linux_sh": str(sh_path),
        "guia_corporativa_md": str(guide_path),
        "total_servicios": len(REVOCATION_URLS)
    }


def _build_powershell_script() -> str:
    urls_block = "\n".join([f'    "{url}" # {desc}' for desc, url in REVOCATION_URLS])
    return f"""<#
.SYNOPSIS
    Guía asistida para revocar sesiones de cuentas en Windows.
.DESCRIPTION
    Abre portales oficiales para que el usuario revise y revoque sesiones.
    No mata procesos ni cambia credenciales o sesiones locales.
.PARAMETER DryRun
    Solo lista los enlaces, sin abrir navegador.
#>
[CmdletBinding()]
param([switch]$DryRun)
$ErrorActionPreference = 'Stop'
$RevocationUrls = @(
{urls_block}
)
Write-Host 'CookieGuard: revocación manual asistida. No se realizarán cambios locales.' -ForegroundColor Cyan
foreach ($url in $RevocationUrls) {{
    Write-Host "Portal oficial: $url"
    if (-not $DryRun) {{ Start-Process $url }}
}}
Write-Host 'En cada portal, cierra las sesiones desconocidas y revoca tokens sospechosos.' -ForegroundColor Yellow
"""


def _build_bash_script() -> str:
    urls_lines = "\n".join([f'  "{url}"' for _, url in REVOCATION_URLS])
    return f"""#!/usr/bin/env bash
# CookieGuard: guía asistida de revocación manual. Sin cambios locales/destructivos.
set -eu
DRY_RUN=false
for arg in "$@"; do
  [ "$arg" = "--dry-run" ] && DRY_RUN=true
done
URLS=(
{urls_lines}
)
echo 'CookieGuard: revocación manual asistida; no se cerrarán navegadores ni se tocarán datos locales.'
for url in "${{URLS[@]}}"; do
  printf 'Portal oficial: %s\n' "$url"
  if [ "$DRY_RUN" = false ] && command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 &
  fi
done
echo 'En cada portal, cierra las sesiones desconocidas y revoca tokens sospechosos.'
"""


def _build_corporate_guide() -> str:
    return """# Guía de Revocación Masiva para Administradores de TI y Ciberseguridad

Si el compromiso de credenciales o cookies afecta a una cuenta corporativa en un entorno
empresarial, los administradores pueden invalidar todas las sesiones concurrentes de forma inmediata:

## 1. Microsoft 365 / Entra ID (Azure AD)
Ejecutar en PowerShell con módulo Microsoft.Graph:
```powershell
# Conectar con privilegios de administrador de usuarios
Connect-MgGraph -Scopes "User.RevokeSessions.All", "Directory.ReadWrite.All"

# Invalidar todos los tokens de actualización (Refresh Tokens) de un usuario
Revoke-MgUserSignInSession -UserId "usuario@tuempresa.com"
```
O mediante el módulo antiguo AzureAD:
```powershell
Revoke-AzureADUserAllRefreshToken -ObjectId "ID_DEL_OBJETO"
```

## 2. Google Workspace
1. Acceder a **Google Workspace Admin Console** (`admin.google.com`).
2. Ir a **Directorio > Usuarios > [Seleccionar Usuario]**.
3. En la sección **Seguridad**, hacer clic en:
   - **Cookies de inicio de sesión > Restablecer**.
   - **Acceso a aplicaciones conectadas > Revocar tokens OAuth sospechosos**.
4. O vía CLI de Google GAM:
```bash
gam user usuario@tuempresa.com signout
```

## 3. GitHub Enterprise / Cloud
1. Ir a **Settings > Sessions**.
2. Hacer clic en **Revoke all sessions**.
3. En **SSH and GPG keys** y **Personal Access Tokens**, revocar cualquier clave no reconocida.

## 4. Amazon Web Services (AWS IAM)
Para revocar sesiones federadas o de consola de un rol/usuario de IAM:
```bash
# Adjuntar política de invalidación temporal con tiempo epoch actual
aws iam put-user-policy --user-name <NombreUsuario> --policy-name RevokeOldSessions --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {"DateLessThan": {"aws:TokenIssueTime": "2026-11-24T09:00:00Z"}}
    }
  ]
}'
```
"""
