#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
if [[ ! -x "${PYTHON_BIN}" ]]; then PYTHON_BIN="python3"; fi

"${PYTHON_BIN}" -m pip install --upgrade pyinstaller
cd "${ROOT_DIR}"
rm -rf build dist
"${PYTHON_BIN}" -m PyInstaller --clean --noconfirm fzz.spec

if [[ -x "dist/fzz" ]]; then chmod +x dist/fzz; fi
printf '\nBuild complete: %s\n' "${ROOT_DIR}/dist/fzz"
