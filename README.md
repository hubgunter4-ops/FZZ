fuzzer HTTP
SQLi: booleanos y pruebas basadas en tiempo.
XSS: contexto HTML y evasión de atributos.
OS Command Injection: Linux/Unix y Windows.
SSTI: motores Jinja2, Twig, FreeMarker, ERB y Pug/Jade.
POST con JSON (application/json), además de GET y POST con formularios.
Payloads definidos en YAML.
Soporte para solicitudes GET y POST.
Configuración de URL, parámetro, método, timeout y pausa.
Detección indicativa de SSTI, lectura de archivos/OS command e inyección basada en tiempo.
Manejo de errores y documentación de uso autorizado.

CLI Python para pruebas de seguridad autorizadas que combine fuzzing HTTP configurable y análisis SAST de archivos y cargas JavaScript.

Architecture: La aplicación se divide en módulos independientes: carga/validación de payloads YAML, cliente de fuzzing HTTP y motor SAST basado en reglas regex. Un punto de entrada CLI expone los comandos fuzz y sast, con límites explícitos de timeout, pausa, tamaño de archivo y alcance del objetivo.

Tech Stack: Python 3.11+, requests, PyYAML, argparse, pytest, Python-tk
(crear interfaz).

El fuzzing soporta GET, POST con formulario y POST con JSON.

•
Los payloads se cargan con yaml.safe_load desde un documento con clave vulnerabilities.

•
El SAST escanea archivos .js y reporta regla, archivo, línea, detalle y código coincidente.

•
El CLI debe devolver códigos de salida útiles.

•
Las solicitudes tienen timeout y pausa configurables (por el usuario dentro de interfaz) para evitar saturación accidental.


