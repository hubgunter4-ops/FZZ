#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${FZZ_VENV:-${ROOT_DIR}/.venv}"
INSTALL_DEV="${FZZ_INSTALL_DEV:-0}"

version_ok="$(${PYTHON_BIN} -c 'import sys; print(int(sys.version_info >= (3, 11)))' 2>/dev/null || echo 0)"
if [[ "$version_ok" != "1" ]]; then
  echo "Error: FZZ requiere Python 3.11 o posterior." >&2
  exit 2
fi

"${PYTHON_BIN}" -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip
"${VENV_DIR}/bin/python" -m pip install -r "${ROOT_DIR}/requirements.txt"
if [[ "$INSTALL_DEV" == "1" ]]; then
  "${VENV_DIR}/bin/python" -m pip install -r "${ROOT_DIR}/requirements-dev.txt"
fi
"${VENV_DIR}/bin/python" -m pip install --editable "${ROOT_DIR}"
"${VENV_DIR}/bin/python" -m fzztool --version

cat <<EOF

FZZ quedó instalado en: ${VENV_DIR}
Activa el entorno con:
  . "${VENV_DIR}/bin/activate"
Ejecuta:
  fzz --help
EOF
