# FZZ — HTTP Fuzzer y SAST para pruebas autorizadas

FZZ es una herramienta educativa para **pruebas de seguridad autorizadas**. Combina fuzzing HTTP configurable con un escáner SAST ligero para archivos JavaScript. No intenta demostrar una explotación ni sustituye una revisión manual. Úsala únicamente contra sistemas propios o con autorización explícita y dentro del alcance acordado.

## Instalación

Requiere Python 3.11 o posterior. En un entorno virtual:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

También puede instalarse como comando local con `pip install -e .`.

## CLI

La entrada principal es `python -m fzztool`; el lanzador `./fzz` ofrece el mismo comportamiento.

```bash
# Fuzzing GET
./fzz fuzz --url http://localhost:3000/search --param q \
  --payloads ./Diccionario\ de\ Cargas\ Útiles\ para\ Pruebas\ de\ Seguridad\" \
  --timeout 10 --pause 0.5

# POST con formulario
./fzz fuzz --url http://localhost:3000/login --param username --method POST --body form

# POST con JSON
./fzz fuzz --url http://localhost:3000/api/login --param username --method POST --body json

# Resultados de fuzzing en JSON
./fzz fuzz --url http://localhost:3000/search --param q --json-output

# SAST recursivo de JavaScript
./fzz sast ./mi-aplicacion
./fzz sast ./mi-aplicacion --json-output
```

El comando `sast` recorre únicamente archivos `.js` y reporta **regla, archivo, línea, detalle y código coincidente**. Las reglas actuales cubren patrones indicativos de SQL construido con entrada HTTP, XSS reflejado o interpolado, APIs de procesos y `eval`.

Los códigos de salida son `0` cuando no se detectan indicadores, `1` cuando existen hallazgos indicativos, `2` para errores de configuración/uso y `3` para errores del sistema.

## Interfaz gráfica

Si Python fue instalado con Tkinter, ejecuta:

```bash
./fzz gui
```

La interfaz permite editar URL, parámetro, método, formato POST, archivo YAML, timeout y pausa. Usa exactamente los mismos servicios que la CLI.

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
