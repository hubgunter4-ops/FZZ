# FZZ — fuzzing HTTP y SAST para pruebas autorizadas

FZZ es una herramienta educativa para ejecutar pruebas de seguridad controladas sobre aplicaciones HTTP y código JavaScript. Incluye un motor de fuzzing HTTP, una fase de reconocimiento previa, descubrimiento opcional de parámetros y un escáner SAST basado en reglas.

> **Uso autorizado únicamente.** Ejecuta FZZ solo contra sistemas propios o contra targets cuyo propietario haya autorizado explícitamente la prueba. Define el alcance, el horario, el volumen máximo de solicitudes y el contacto operativo antes de iniciar cualquier ejecución.

FZZ genera **indicadores**, no pruebas concluyentes de explotación. Todo hallazgo requiere revisión manual y validación dentro del alcance aprobado.

## Funcionalidades principales

- **Reconocimiento HTTP acotado:** valida el target y realiza una única solicitud GET antes del fuzzing.
- **Perfil del target:** registra estado HTTP, URL final, título, tipo de contenido, tamaño, servidor, tecnología declarada y métodos permitidos.
- **Parámetros automáticos:** extrae nombres de la query string y de campos HTML `input`, `textarea` y `select` sin hacer crawling ni enviar formularios.
- **Fuzzing GET y POST:** admite formularios y JSON, con timeout, pausa y límite de solicitudes configurables.
- **Carga YAML validada:** normaliza categorías, técnicas y payloads con `yaml.safe_load` y límites de tamaño.
- **Detección conservadora:** identifica indicadores reflejados o relacionados con las reglas disponibles, pero no afirma explotación.
- **SAST JavaScript:** recorre archivos `.js` y reports reglas, archivo, línea, detalle y código coincidente.
- **Interfaz Tkinter:** ofrece un panel visual de alto contraste con reconocimiento, configuración y consola de resultados.
- **Distribución independiente:** PyInstaller empaqueta CLI y GUI en un ejecutable único.
- **CI multiplataforma:** GitHub Actions construye bundles para Linux, Windows y macOS.

## Requisitos

Para ejecutar desde el código fuente se necesita:

- Python 3.11 o posterior.
- `pip` y `venv`.
- Acceso de red al target autorizado cuando se use `recon` o `fuzz`.
- Tkinter únicamente para la interfaz gráfica.

En Ubuntu o Debian, instala Tkinter con:

```bash
sudo apt-get update
sudo apt-get install -y python3-tk
```

Para construir ejecutables Linux con PyInstaller también se necesita `binutils`, que normalmente puede instalarse con:

```bash
sudo apt-get install -y binutils
```

Windows y macOS deben usar una distribución de Python que incluya Tkinter si se desea ejecutar la GUI.

## Instalación desde el repositorio

### Linux y macOS: instalación automática

El instalador crea un entorno virtual aislado, instala las dependencias runtime y registra FZZ en modo editable:

```bash
git clone https://github.com/hubgunter4-ops/FZZ.git
cd FZZ
./scripts/install.sh
. .venv/bin/activate
fzz --help
```

El instalador acepta estas variables opcionales:

```bash
PYTHON_BIN=python3.12 FZZ_VENV=.fzz-venv ./scripts/install.sh
```

Para incluir pruebas y herramientas de construcción:

```bash
FZZ_INSTALL_DEV=1 ./scripts/install.sh
```

### Instalación manual

```bash
git clone https://github.com/hubgunter4-ops/FZZ.git
cd FZZ
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

La instalación editable permite ejecutar `fzz` desde cualquier directorio mientras se trabaja sobre el código fuente.

### Windows PowerShell

```powershell
git clone https://github.com/hubgunter4-ops/FZZ.git
Set-Location FZZ
.\scripts\install.ps1
.\.venv\Scripts\Activate.ps1
fzz --help
```

Para instalar dependencias de desarrollo:

```powershell
$env:FZZ_INSTALL_DEV = "1"
.\scripts\install.ps1
```

### Instalación para desarrollo con Make

```bash
make install-dev
make check
```

Los comandos disponibles son:

| Comando | Función |
|---|---|
| `make install` | Instala dependencias runtime en `.venv`. |
| `make install-dev` | Instala runtime, pruebas y PyInstaller. |
| `make test` | Ejecuta la suite de pruebas. |
| `make check` | Compila módulos, ejecuta pruebas y verifica la ayuda CLI. |
| `make package` | Genera el ejecutable con PyInstaller. |
| `make clean` | Elimina artefactos locales de build y pruebas. |

## Inicio rápido

La CLI puede ejecutarse de tres formas equivalentes:

```bash
./fzz --help
python -m fzztool --help
fzz --help
```

Reconocimiento independiente:

```bash
./fzz recon --url https://app.example.test/search
```

Reconocimiento en JSON:

```bash
./fzz recon \
  --url https://app.example.test/search \
  --json-output
```

Fuzzing de un parámetro específico:

```bash
./fzz fuzz \
  --url https://app.example.test/search \
  --param q \
  --payloads ./resources/payloads.yml \
  --timeout 10 \
  --pause 0.5 \
  --max-requests 50
```

Escaneo SAST:

```bash
./fzz sast ./mi-aplicacion
./fzz sast ./mi-aplicacion --json-output
```

## Flujo de reconocimiento y fuzzing

El comando `fuzz` valida primero la configuración y el target. Después ejecuta una sola solicitud GET con redirecciones habilitadas. Si esa fase falla, no se envían payloads.

El perfil obtenido contiene:

- URL solicitada y URL final después de redirecciones.
- Estado HTTP y tiempo transcurrido.
- Título HTML, tipo de contenido y longitud declarada.
- Cabeceras `Server`, `X-Powered-By` y `Allow`, cuando existen.
- Parámetros candidatos detectados durante el análisis del contenido.

El recon no sigue enlaces, no realiza crawling, no envía formularios y no ejecuta payloads. El cuerpo analizado está limitado a 512 KB.

## Parámetros automáticos

El modo automático se activa explícitamente con `--auto-params`:

```bash
./fzz fuzz \
  --url http://localhost:3000/search \
  --auto-params \
  --payloads ./resources/payloads.yml \
  --max-requests 50
```

FZZ combina los nombres presentes en la query string con los atributos `name` de los elementos HTML `input`, `textarea` y `select`. El resultado se deduplica y se limita a 32 candidatos. Después distribuye las solicitudes entre esos parámetros hasta alcanzar `--max-requests`.

`--param NOMBRE` y `--auto-params` son opciones mutuamente excluyentes. Si no se encuentra ningún candidato, FZZ detiene la ejecución en lugar de adivinar nombres o iniciar crawling.

Cada resultado conserva el parámetro usado, tanto en la salida normal como en JSON:

```text
[200] 0.31s [query] xss/Reflejado Básico: <svg/onload=alert(1)>
```

## Fuzzing HTTP

### GET

```bash
./fzz fuzz \
  --url http://localhost:3000/search \
  --param q \
  --method GET
```

El payload se añade como parámetro de query mediante la biblioteca `requests`.

### POST con formulario

```bash
./fzz fuzz \
  --url http://localhost:3000/login \
  --param username \
  --method POST \
  --body form
```

### POST con JSON

```bash
./fzz fuzz \
  --url http://localhost:3000/api/search \
  --param query \
  --method POST \
  --body json
```

Parámetros de control:

| Opción | Predeterminado | Límite | Descripción |
|---|---:|---:|---|
| `--timeout` | `10` | `120` segundos | Tiempo máximo por solicitud de fuzzing. |
| `--pause` | `0.5` | `60` segundos | Espera entre solicitudes. |
| `--max-requests` | `500` | `500` | Límite total por ejecución. |
| `--payloads` | `resources/payloads.yml` | `1 MB` | Diccionario YAML utilizado. |

## Interfaz gráfica Tkinter

Inicia el panel con:

```bash
./fzz gui
```

La interfaz usa un diseño de control para herramientas técnicas. Incluye navegación lateral, tarjetas de estado, formulario de configuración y consola de resultados. El estado del flujo se muestra mediante `READY`, `RUNNING`, `RECON VALIDATED`, `COMPLETE` y `BLOCKED`.

El panel permite configurar URL, parámetro, detección automática, archivo YAML, método, formato POST, timeout y pausa. La opción **Detectar parámetros automáticamente desde recon** activa el mismo comportamiento de `--auto-params`.

Atajos disponibles:

- `Ctrl+Enter`: inicia una ejecución.
- `Escape`: informa que existe una ejecución en curso.

La consola diferencia reconocimiento, resultados con indicadores y errores. El reconocimiento aparece siempre antes de los resultados de payloads.

## Formato del diccionario YAML

El documento debe contener `vulnerabilities`, un mapa de categorías. Cada categoría contiene una lista de técnicas y cada técnica contiene una lista de payloads:

```yaml
version: "2.0"
description: "Payloads de prueba autorizada"
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

FZZ valida el documento con `yaml.safe_load`. Los valores de payload pueden ser texto, enteros o números decimales; se normalizan a texto antes de enviarse. Un documento vacío, mal formado o superior a 1 MB se rechaza.

El recurso `resources/payloads.yml` se incluye en el repositorio y también se embebe en el ejecutable PyInstaller.

## SAST JavaScript

El comando `sast` recorre recursivamente archivos con extensión `.js`. Las reglas actuales buscan patrones indicativos de:

- Construcción de SQL con entrada HTTP.
- XSS reflejado o interpolado.
- Uso de `eval`.
- APIs de procesos o ejecución de comandos.

Ejemplo de salida JSON:

```bash
./fzz sast ./src --json-output > findings.json
```

Los resultados incluyen regla, archivo, línea, detalle y código coincidente. El escáner es deliberadamente ligero y basado en expresiones regulares; debe complementarse con revisión manual y herramientas SAST especializadas cuando el riesgo lo requiera.

## Códigos de salida

| Código | Significado |
|---:|---|
| `0` | Ejecución correcta sin indicadores o reconocimiento correcto. |
| `1` | Se detectaron indicadores de seguridad o hallazgos SAST. |
| `2` | Error de configuración, validación o target. |
| `3` | Error del sistema operativo o de ejecución. |

## Ejecutable independiente con PyInstaller

FZZ se empaqueta como un único ejecutable que contiene CLI, GUI, dependencias Python y el diccionario de payloads. PyInstaller debe ejecutarse en el mismo sistema operativo y arquitectura del destino; no realiza compilación cruzada.

### Linux y macOS

```bash
make install-dev
make package
./dist/fzz --version
./dist/fzz --help
./dist/fzz gui
```

El script [`scripts/build.sh`](scripts/build.sh) instala o actualiza PyInstaller, limpia `build/` y `dist/`, ejecuta `fzz.spec` y deja el resultado en `dist/fzz`.

### Windows

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
.\scripts\build.ps1
.\dist\fzz.exe --version
.\dist\fzz.exe gui
```

El script [`scripts/build.ps1`](scripts/build.ps1) genera `dist\fzz.exe`. Los directorios `build/` y `dist/` están excluidos de Git.

## Docker

La imagen Docker contiene la CLI y sus dependencias runtime:

```bash
docker build -t fzz-security-tool .
docker run --rm fzz-security-tool --help
docker run --rm fzz-security-tool recon --url https://app.example.test
```

El Dockerfile está pensado para uso de CLI. La GUI Tkinter debe ejecutarse desde una instalación local con acceso a un servidor gráfico.

## GitHub Actions

El workflow [`build.yml`](.github/workflows/build.yml) ejecuta calidad y builds nativos para:

- Linux x86_64: `fzz-linux-x86_64`.
- Windows x86_64: `fzz-windows-x86_64.exe`.
- macOS x86_64: `fzz-macos-x86_64`.

Se activa en pull requests, pushes a `main`, tags `v*` y ejecuciones manuales. El job de calidad compila módulos y ejecuta la suite antes de iniciar la matriz de builds. Cada plataforma publica un artifact con retención de 14 días.

Para crear una release distribuible:

```bash
git tag v1.0.0
git push origin v1.0.0
```

El job de release descarga los tres ejecutables, genera `SHA256SUMS.txt` y crea una GitHub Release con notas automáticas. El workflow usa permisos de lectura por defecto y concede escritura únicamente al job que publica la release.

## Arquitectura del proyecto

```text
fzztool/
├── cli.py          # comandos fuzz, recon, sast y gui
├── detectors.py    # indicadores conservadores de respuestas
├── fuzzer.py       # motor HTTP y límites de solicitudes
├── gui.py          # panel Tkinter
├── payloads.py     # carga, validación y normalización YAML
├── recon.py        # validación, perfilado y candidatos de parámetros
└── sast.py         # escáner SAST JavaScript

resources/payloads.yml       # diccionario distribuible
packaging/fzz_entry.py       # entrada PyInstaller
fzz.spec                     # configuración del bundle
scripts/install.*             # instaladores locales
scripts/build.*               # builds PyInstaller
.github/workflows/build.yml   # CI y releases multiplataforma
tests/                        # pruebas unitarias
```

Los archivos heredados sin extensión —`fuzz`, `parser`, `pay` y `rules`— se conservan como prototipos históricos. Los diccionarios heredados se conservan como `payloads-legacy-full.yml` y `payloads-legacy-basic.yml`; sus nombres no contienen caracteres inválidos para Windows. La implementación mantenible está en `fzztool/`.

## Desarrollo y verificación

Después de modificar el proyecto, ejecuta:

```bash
make check
python -m compileall -q fzztool packaging
```

Para probar la interfaz en un entorno Linux con display virtual:

```bash
xvfb-run -a python -c 'import tkinter as tk; from fzztool.gui import FZZApp; root=tk.Tk(); FZZApp(root); root.destroy()'
```

Antes de distribuir un bundle, verifica al menos:

```bash
./dist/fzz --version
./dist/fzz --help
```

## Limitaciones y uso responsable

FZZ no realiza crawling, no autentica usuarios, no intenta evadir controles de acceso y no verifica de forma concluyente la explotación de una vulnerabilidad. El modo automático solo reutiliza nombres observados en la respuesta inicial; no inventa parámetros ni descubre rutas adicionales.

Una respuesta que contiene un marcador puede ser un falso positivo. Revisa el contexto de reflexión, repite la prueba con una carga inocua y conserva evidencia únicamente dentro de las políticas aprobadas. Ajusta `--pause` y `--max-requests` para no degradar el servicio probado.

## Referencias

[1]: https://docs.python.org/3/library/venv.html "Python venv documentation"

[2]: https://pyinstaller.org/en/stable/ "PyInstaller documentation"

[3]: https://docs.github.com/en/actions "GitHub Actions documentation"

[4]: https://docs.python-requests.org/en/latest/ "Requests documentation"

[5]: https://pyyaml.org/wiki/PyYAMLDocumentation "PyYAML documentation"
