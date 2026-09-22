PYTHON ?= python3
VENV ?= .venv
VENV_PYTHON = $(VENV)/bin/python

.PHONY: install install-dev test check help clean

install:
	PYTHON_BIN=$(PYTHON) FZZ_VENV=$(VENV) ./scripts/install.sh

install-dev:
	PYTHON_BIN=$(PYTHON) FZZ_VENV=$(VENV) FZZ_INSTALL_DEV=1 ./scripts/install.sh

test:
	$(VENV_PYTHON) -m pytest -q

check:
	$(VENV_PYTHON) -m compileall -q fzztool
	$(VENV_PYTHON) -m pytest -q
	$(VENV_PYTHON) -m fzztool --help

help:
	@printf '%s\n' 'make install      Instala dependencias runtime y FZZ en .venv' \
	              'make install-dev  Instala runtime, pytest y herramientas de desarrollo' \
	              'make test         Ejecuta las pruebas' \
	              'make check        Compila, prueba y verifica la ayuda CLI'

clean:
	rm -rf build dist *.egg-info .pytest_cache
