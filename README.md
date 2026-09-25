# FZZ — HTTP Fuzzer y SAST para pruebas autorizadas

FZZ es una herramienta educativa para **pruebas de seguridad autorizadas**. Combina fuzzing HTTP configurable con un escáner SAST ligero para archivos JavaScript. No intenta demostrar una explotación ni sustituye una revisión manual. Úsala únicamente contra sistemas propios o con autorización explícita y dentro del alcance acordado.

## Instalación

Requiere Python 3.11 o posterior. En un entorno virtual:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Para automatizar esos pasos en Linux o macOS:

```bash
./scripts/install.sh
```

Para instalar también las dependencias de desarrollo y pruebas:

```bash
make install-dev
make check
```

En Windows PowerShell puede usarse `scripts\install.ps1`; el instalador acepta `PYTHON_BIN`, `FZZ_VENV` y `FZZ_INSTALL_DEV=1` como variables opcionales. También puede instalarse como comando local con `pip install -e .`.

### Ejecución con Docker

La imagen contiene la CLI y sus dependencias runtime. Construye y ejecuta siempre con un target autorizado:

```bash
docker build -t fzz-security-tool .
docker run --rm fzz-security-tool --help
docker run --rm fzz-security-tool recon --url https://example.com
```

El `Dockerfile` no incluye la GUI Tkinter ni los payloads heredados; para la interfaz gráfica usa una instalación local y para un diccionario propio monta el archivo como volumen.

## CLI

La entrada principal es `python -m fzztool`; el lanzador `./fzz` ofrece el mismo comportamiento.

Antes de enviar payloads, `fuzz` ejecuta una fase de reconocimiento de **una sola solicitud GET** contra el target introducido. La herramienta valida el esquema HTTP(S), hostname, puerto y ausencia de credenciales embebidas; después registra estado, URL final, título, tipo de contenido y cabeceras informativas. Si el target no es válido o no puede contactarse, el fuzzing no comienza. Esta fase no hace crawling ni inyecta payloads.

También puede ejecutarse de forma independiente:

```bash
./fzz recon --url https://localhost:3000/health
./fzz recon --url https://localhost:3000/health --json-output
```

```bash
# Fuzzing GET (incluye reconocimiento previo)
./fzz fuzz --url http://localhost:3000/search --param q \
  --payloads ./Diccionario\ de\ Cargas\ Útiles\ para\ Pruebas\ de\ Seguridad\" \
  --timeout 10 --pause 0.5

# POST con formulario
./fzz fuzz --url http://localhost:3000/login --param username --method POST --body form

# POST con JSON
./fzz fuzz --url http://localhost:3000/api/login --param username --method POST --body json

# Resultados de reconocimiento y fuzzing en JSON
./fzz fuzz --url http://localhost:3000/search --param q --json-output

# SAST recursivo de JavaScript
./fzz sast ./mi-aplicacion
./fzz sast ./mi-aplicacion --json-output
```

El comando `sast` recorre únicamente archivos `.js` y reporta **regla, archivo, línea, detalle y código coincidente**. Las reglas actuales cubren patrones indicativos de SQL construido con entrada HTTP, XSS reflejado o interpolado, APIs de procesos y `eval`.

Los códigos de salida son `0` cuando no se detectan indicadores o el reconocimiento es correcto, `1` cuando existen hallazgos indicativos, `2` para errores de configuración/validación del target y `3` para errores del sistema.

## Interfaz gráfica

La interfaz Tkinter usa un panel de control de alto contraste inspirado en el patrón **Utility/Tool Control Panel**: navegación lateral, tarjetas de estado, configuración agrupada y consola de resultados. Sigue una cuadrícula de espaciado de 8 puntos, utiliza controles nativos enfocados por teclado y mantiene visibles los estados `READY`, `RUNNING`, `RECON VALIDATED`, `COMPLETE` y `BLOCKED`.

Requiere el módulo de escritorio Tkinter. En Ubuntu/Debian:

```bash
sudo apt-get install python3-tk
```

En Windows y macOS, usa una distribución de Python que incluya Tkinter. Después ejecuta:

```bash
./fzz gui
```

La interfaz permite editar URL, parámetro, método, formato POST, archivo YAML, timeout y pausa. Usa exactamente los mismos servicios que la CLI.

El botón principal puede activarse con `Ctrl+Enter`; `Escape` informa del estado de una ejecución en curso. La consola diferencia visualmente reconocimiento, hallazgos y errores, y el reconocimiento siempre aparece antes de cualquier payload.

## Formato YAML

El documento debe contener una clave `vulnerabilities` con categorías, técnicas y listas de payloads:

```yaml
vulnerabilities:
  ssti:
    - technique: "Expresiones aritméticas"
      payloads:
        - "{{7*7}}"
  xss:
    - technique: "Contexto HTML"
      payloads:
        - "<test>"
```

La herramienta carga este documento con `yaml.safe_load`, valida su estructura y limita el archivo a 1 MB. El fuzzing limita el timeout a 120 segundos, la pausa a 60 segundos y cada ejecución a 500 solicitudes como protección contra saturación accidental.

## Compatibilidad con el repositorio original

Los archivos sin extensión `fuzz`, `parser`, `pay` y `rules` se conservan como prototipos históricos. La implementación mantenible está en `fzztool/`; evita duplicar lógica en los prototipos. El diccionario de cargas heredado se acepta como entrada predeterminada.

## Desarrollo y pruebas

```bash
python -m pytest -q
python -m compileall -q fzztool
./fzz --help
```

Los hallazgos de fuzzing son indicadores conservadores: una respuesta que contiene un marcador no confirma por sí sola una vulnerabilidad. Revisa las respuestas, reproduce de forma controlada y documenta siempre el alcance autorizado.
