"""High-contrast Tkinter control panel for FZZ authorized security testing."""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from .fuzzer import FuzzConfig, FuzzResult, fuzz_target
from .payloads import default_check_file, default_payload_file, load_payloads
from .recon import ReconError, ReconProfile
from .sast import scan_directory


# Design tokens: 8pt rhythm, high contrast, restrained utility-tool palette.
COLORS = {
    "canvas": "#0B1220",
    "sidebar": "#101A2D",
    "panel": "#16243A",
    "panel_alt": "#1B2D48",
    "border": "#2C4363",
    "text": "#F4F7FB",
    "muted": "#AFC0D6",
    "accent": "#4FD1C5",
    "accent_dark": "#153F43",
    "warning": "#F6C85F",
    "danger": "#FF8B8B",
    "success": "#79E2A5",
}


class FZZApp:
    """Atomic-design-inspired desktop shell around the existing FZZ services."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("FZZ  /  Security Control Panel")
        self.root.geometry("1180x760")
        self.root.minsize(940, 640)
        self.root.configure(bg=COLORS["canvas"])
        self._configure_styles()
        self._build_shell()
        self._bind_shortcuts()

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("App.TFrame", background=COLORS["canvas"])
        style.configure("Sidebar.TFrame", background=COLORS["sidebar"])
        style.configure("Panel.TFrame", background=COLORS["panel"])
        style.configure("Card.TFrame", background=COLORS["panel_alt"])
        style.configure("Title.TLabel", background=COLORS["canvas"], foreground=COLORS["text"], font=("TkDefaultFont", 22, "bold"))
        style.configure("Subtitle.TLabel", background=COLORS["canvas"], foreground=COLORS["muted"], font=("TkDefaultFont", 10))
        style.configure("Section.TLabel", background=COLORS["panel"], foreground=COLORS["text"], font=("TkDefaultFont", 12, "bold"))
        style.configure("Field.TLabel", background=COLORS["panel"], foreground=COLORS["muted"], font=("TkDefaultFont", 9, "bold"))
        style.configure("CardTitle.TLabel", background=COLORS["panel_alt"], foreground=COLORS["muted"], font=("TkDefaultFont", 9, "bold"))
        style.configure("CardValue.TLabel", background=COLORS["panel_alt"], foreground=COLORS["text"], font=("TkDefaultFont", 14, "bold"))
        style.configure("Body.TLabel", background=COLORS["panel"], foreground=COLORS["text"], font=("TkDefaultFont", 10))
        style.configure("TEntry", fieldbackground="#0F1B2E", foreground=COLORS["text"], insertcolor=COLORS["text"], bordercolor=COLORS["border"], padding=8)
        style.configure("TCombobox", fieldbackground="#0F1B2E", foreground=COLORS["text"], arrowsize=14, padding=7)
        style.map("TCombobox", fieldbackground=[("readonly", "#0F1B2E")], foreground=[("readonly", COLORS["text"])])
        style.configure("Accent.TButton", background=COLORS["accent"], foreground="#071517", font=("TkDefaultFont", 10, "bold"), padding=(16, 10), borderwidth=0)
        style.map("Accent.TButton", background=[("active", "#76E5DB"), ("disabled", "#436966")])
        style.configure("Secondary.TButton", background=COLORS["panel_alt"], foreground=COLORS["text"], padding=(12, 9), borderwidth=1)
        style.map("Secondary.TButton", background=[("active", COLORS["border"])])
        style.configure("Nav.TButton", background=COLORS["sidebar"], foreground=COLORS["muted"], anchor="w", padding=(16, 10), borderwidth=0)
        style.map("Nav.TButton", background=[("active", COLORS["panel_alt"])], foreground=[("active", COLORS["text"])])
        style.configure("Status.TLabel", background=COLORS["canvas"], foreground=COLORS["muted"], font=("TkDefaultFont", 9))

    def _build_shell(self) -> None:
        shell = ttk.Frame(self.root, style="App.TFrame")
        shell.pack(fill="both", expand=True)
        shell.columnconfigure(1, weight=1)
        shell.rowconfigure(0, weight=1)

        sidebar = ttk.Frame(shell, style="Sidebar.TFrame", padding=(0, 24, 0, 16))
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.configure(width=216)
        sidebar.grid_propagate(False)
        self._build_sidebar(sidebar)

        main = ttk.Frame(shell, style="App.TFrame", padding=(32, 28, 32, 18))
        main.grid(row=0, column=1, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(2, weight=1)
        self._build_header(main)
        self._build_cards(main)
        self._build_workspace(main)
        self.status = ttk.Label(main, text="Listo · Solo pruebas autorizadas", style="Status.TLabel")
        self.status.grid(row=3, column=0, sticky="w", pady=(12, 0))

    def _build_sidebar(self, sidebar: ttk.Frame) -> None:
        brand = tk.Label(sidebar, text="FZZ", bg=COLORS["sidebar"], fg=COLORS["accent"], font=("TkDefaultFont", 25, "bold"), anchor="w")
        brand.pack(fill="x", padx=20)
        tk.Label(sidebar, text="SECURITY TOOLKIT", bg=COLORS["sidebar"], fg=COLORS["muted"], font=("TkDefaultFont", 8, "bold"), anchor="w").pack(fill="x", padx=22, pady=(0, 28))
        for label, command in (("⌂   Overview", self._focus_workspace), ("◎   Target recon", self._focus_workspace), ("⌁   HTTP fuzzing", self._focus_workspace), ("▣   JavaScript SAST", self._start_sast)):
            ttk.Button(sidebar, text=label, style="Nav.TButton", command=command).pack(fill="x", pady=2)
        spacer = ttk.Frame(sidebar, style="Sidebar.TFrame")
        spacer.pack(fill="both", expand=True)
        tk.Label(sidebar, text="AUTHORIZED USE ONLY", bg=COLORS["sidebar"], fg=COLORS["warning"], font=("TkDefaultFont", 8, "bold"), anchor="w").pack(fill="x", padx=22)
        tk.Label(sidebar, text="FZZ 1.0.0", bg=COLORS["sidebar"], fg=COLORS["muted"], font=("TkDefaultFont", 8), anchor="w").pack(fill="x", padx=22, pady=(4, 0))

    def _build_header(self, parent: ttk.Frame) -> None:
        header = ttk.Frame(parent, style="App.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 22))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Security control panel", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(header, text="Reconoce el target, valida el alcance y ejecuta pruebas controladas.", style="Subtitle.TLabel").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.header_badge = tk.Label(header, text="●  READY", bg=COLORS["accent_dark"], fg=COLORS["accent"], font=("TkDefaultFont", 9, "bold"), padx=12, pady=7)
        self.header_badge.grid(row=0, column=1, rowspan=2, sticky="e")

    def _build_cards(self, parent: ttk.Frame) -> None:
        cards = ttk.Frame(parent, style="App.TFrame")
        cards.grid(row=1, column=0, sticky="ew", pady=(0, 22))
        for col in range(4):
            cards.columnconfigure(col, weight=1)
        self.card_values: dict[str, tk.StringVar] = {}
        for col, (key, title, value) in enumerate((("target", "TARGET STATUS", "Not checked"), ("status", "HTTP STATUS", "—"), ("title", "PAGE TITLE", "—"), ("content", "CONTENT TYPE", "—"))):
            card = ttk.Frame(cards, style="Card.TFrame", padding=(14, 12))
            card.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 6, 0))
            ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="w")
            self.card_values[key] = tk.StringVar(value=value)
            ttk.Label(card, textvariable=self.card_values[key], style="CardValue.TLabel").pack(anchor="w", pady=(8, 0))

    def _build_workspace(self, parent: ttk.Frame) -> None:
        workspace = ttk.Frame(parent, style="App.TFrame")
        workspace.grid(row=2, column=0, sticky="nsew")
        workspace.columnconfigure(0, weight=0, minsize=410)
        workspace.columnconfigure(1, weight=1)
        workspace.rowconfigure(0, weight=1)
        self._build_config_panel(workspace)
        self._build_console(workspace)

    def _build_config_panel(self, parent: ttk.Frame) -> None:
        panel = ttk.Frame(parent, style="Panel.TFrame", padding=20)
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        panel.columnconfigure(0, weight=1)
        ttk.Label(panel, text="Test configuration", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(panel, text="Define el target y los límites antes de ejecutar.", style="Body.TLabel").grid(row=1, column=0, sticky="w", pady=(5, 18))
        self.fields: dict[str, tk.StringVar] = {}
        defaults = {"url": "http://localhost:3000/", "param": "q", "payloads": str(default_check_file()), "timeout": "10", "pause": "0.5"}
        rows = (("url", "TARGET URL", "http(s)://..."), ("param", "PARAMETER", "q"), ("payloads", "PAYLOAD YAML", "Selecciona un archivo"), ("timeout", "TIMEOUT (SECONDS)", "10"), ("pause", "PAUSE BETWEEN REQUESTS", "0.5"))
        for index, (key, label, hint) in enumerate(rows):
            row = 2 + (index * 2)
            ttk.Label(panel, text=label, style="Field.TLabel").grid(row=row, column=0, sticky="w", pady=(8, 5))
            self.fields[key] = tk.StringVar(value=defaults[key])
            holder = ttk.Frame(panel, style="Panel.TFrame")
            holder.grid(row=row + 1, column=0, sticky="ew", pady=(0, 4))
            holder.columnconfigure(0, weight=1)
            entry = ttk.Entry(holder, textvariable=self.fields[key])
            entry.grid(row=0, column=0, sticky="ew")
            if key == "payloads":
                ttk.Button(holder, text="Browse", style="Secondary.TButton", command=self._browse_payloads).grid(row=0, column=1, padx=(6, 0))
            entry.bind("<FocusIn>", lambda event, h=hint: self._set_status(f"Campo activo · {h}"))
        self.safe_checks = tk.BooleanVar(value=True)
        ttk.Checkbutton(panel, text="Usar comprobaciones seguras precargadas", variable=self.safe_checks, command=self._toggle_safe_checks).grid(row=12, column=0, sticky="w", pady=(8, 5))
        self.auto_params = tk.BooleanVar(value=False)
        ttk.Checkbutton(panel, text="Detectar parámetros automáticamente desde recon", variable=self.auto_params).grid(row=13, column=0, sticky="w", pady=(8, 5))
        ttk.Label(panel, text="METHOD", style="Field.TLabel").grid(row=15, column=0, sticky="w", pady=(8, 5))
        self.method = tk.StringVar(value="GET")
        ttk.Combobox(panel, textvariable=self.method, values=("GET", "POST"), state="readonly").grid(row=16, column=0, sticky="ew")
        ttk.Label(panel, text="POST BODY", style="Field.TLabel").grid(row=17, column=0, sticky="w", pady=(8, 5))
        self.body = tk.StringVar(value="form")
        ttk.Combobox(panel, textvariable=self.body, values=("form", "json"), state="readonly").grid(row=18, column=0, sticky="ew")
        panel.rowconfigure(19, weight=1)
        action = ttk.Frame(panel, style="Panel.TFrame")
        action.grid(row=20, column=0, sticky="ew", pady=(20, 0))
        action.columnconfigure(0, weight=1)
        ttk.Button(action, text="Run authorized test", style="Accent.TButton", command=self._start_run).grid(row=0, column=0, sticky="ew")
        ttk.Button(action, text="Clear console", style="Secondary.TButton", command=self._clear_console).grid(row=1, column=0, sticky="ew", pady=(8, 0))

    def _build_console(self, parent: ttk.Frame) -> None:
        panel = ttk.Frame(parent, style="Panel.TFrame", padding=20)
        panel.grid(row=0, column=1, sticky="nsew")
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(2, weight=1)
        top = ttk.Frame(panel, style="Panel.TFrame")
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(0, weight=1)
        ttk.Label(top, text="Live results", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.result_count = tk.StringVar(value="0 events")
        ttk.Label(top, textvariable=self.result_count, style="Subtitle.TLabel").grid(row=0, column=1, sticky="e")
        ttk.Label(panel, text="Recognition appears first; payload results follow only after target validation.", style="Body.TLabel").grid(row=1, column=0, sticky="w", pady=(5, 12))
        text_frame = ttk.Frame(panel, style="Panel.TFrame")
        text_frame.grid(row=2, column=0, sticky="nsew")
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)
        self.output = tk.Text(text_frame, bg="#0A1424", fg=COLORS["text"], insertbackground=COLORS["accent"], selectbackground=COLORS["border"], relief="flat", borderwidth=0, padx=14, pady=14, wrap="word", font=("TkFixedFont", 10), state="disabled")
        self.output.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(text_frame, orient="vertical", command=self.output.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.output.configure(yscrollcommand=scroll.set)
        self.output.tag_configure("recon", foreground=COLORS["accent"], font=("TkFixedFont", 10, "bold"))
        self.output.tag_configure("finding", foreground=COLORS["warning"])
        self.output.tag_configure("error", foreground=COLORS["danger"])
        self.output.tag_configure("muted", foreground=COLORS["muted"])

    def _bind_shortcuts(self) -> None:
        self.root.bind("<Control-Return>", lambda event: self._start_run())
        self.root.bind("<Escape>", lambda event: self._set_status("Ejecución en curso; espera a que termine la solicitud actual"))

    def _focus_workspace(self) -> None:
        self.fields["url"].focus_set()

    def _browse_payloads(self) -> None:
        chosen = filedialog.askopenfilename(title="Seleccionar payload YAML", filetypes=(("YAML", "*.yml *.yaml"), ("Todos los archivos", "*.*")))
        if chosen:
            self.fields["payloads"].set(chosen)
            self._set_status("Archivo de payload seleccionado")

    def _toggle_safe_checks(self) -> None:
        if self.safe_checks.get():
            self.fields["payloads"].set(str(default_check_file()))
            self._set_status("Comprobaciones seguras precargadas")
        else:
            self.fields["payloads"].set(str(default_payload_file()))
            self._set_status("Diccionario general seleccionado; revisa el alcance")

    def _start_sast(self) -> None:
        directory = filedialog.askdirectory(title="Seleccionar directorio JavaScript para SAST")
        if not directory:
            return
        self._clear_console()
        self.header_badge.configure(text="●  SAST RUNNING", bg="#4A3B19", fg=COLORS["warning"])
        self._set_status("Escaneando JavaScript con reglas de criptografía y secretos…", tone="warning")
        self._write(f"[SAST] Directorio: {directory}\n", "muted")
        try:
            findings = scan_directory(directory)
        except (OSError, ValueError) as exc:
            self.header_badge.configure(text="●  BLOCKED", bg="#4A2024", fg=COLORS["danger"])
            self._set_status("SAST bloqueado: revisa el directorio", tone="danger")
            self._write(f"[SAST] [!] {exc}\n", "error")
            return
        self.result_count.set(f"{len(findings)} findings")
        for finding in findings:
            self._write(f"[{finding.severity.upper()}] {finding.rule}  {finding.file}:{finding.line}\n", "finding")
            self._write(f"  {finding.detail}\n  {finding.code}\n\n")
        self.header_badge.configure(text="●  SAST COMPLETE", bg="#193C2B", fg=COLORS["success"])
        self._set_status(f"SAST completado · {len(findings)} hallazgo(s); revisa contexto y confianza")

    def _set_status(self, value: str, *, tone: str = "normal") -> None:
        self.status.configure(text=value, foreground=COLORS.get(tone, COLORS["muted"]))

    def _clear_console(self) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        self.result_count.set("0 events")
        self._set_status("Consola limpia")

    def _write(self, text: str, tag: str = "") -> None:
        self.output.configure(state="normal")
        self.output.insert("end", text, tag)
        self.output.see("end")
        self.output.configure(state="disabled")

    def _update_recon(self, profile: ReconProfile) -> None:
        self.card_values["target"].set("Validated")
        self.card_values["status"].set(str(profile.status_code))
        self.card_values["title"].set(profile.title or "No title")
        self.card_values["content"].set((profile.content_type or "Unknown").split(";", 1)[0])
        self.header_badge.configure(text="●  RECON VALIDATED", bg=COLORS["accent_dark"], fg=COLORS["accent"])
        self._write(f"[RECON] {profile.status_code}  {profile.final_url}\n", "recon")
        self._write(f"        parameters={', '.join(profile.parameters) if profile.parameters else 'none detected'}\n", "muted")
        self._write(f"        title={profile.title or 'n/d'}  content={profile.content_type or 'n/d'}  elapsed={profile.elapsed:.2f}s\n\n", "muted")

    def _update_result(self, result: FuzzResult) -> None:
        current = int(self.result_count.get().split()[0]) + 1
        self.result_count.set(f"{current} events")
        status = result.status_code if result.status_code is not None else "ERROR"
        tag = "error" if result.error else ("finding" if result.indicators else "")
        self._write(f"[{status}] {result.elapsed:.2f}s  [{result.parameter}] {result.category}/{result.technique}\n  {result.payload}\n", tag)
        for indicator in result.indicators:
            self._write(f"  [!] {indicator}\n", "finding")
        if result.error:
            self._write(f"  [!] {result.error}\n", "error")
        self._write("\n")

    def _start_run(self) -> None:
        if not self.fields["url"].get().strip():
            messagebox.showerror("Target requerido", "Introduce una URL HTTP(S) antes de ejecutar.")
            self.fields["url"].focus_set()
            return
        self._clear_console()
        self.header_badge.configure(text="●  RUNNING", bg="#4A3B19", fg=COLORS["warning"])
        self._set_status("Reconociendo target y validando alcance…", tone="warning")
        self._write("[SYSTEM] Iniciando reconocimiento previo.\n\n", "muted")
        threading.Thread(target=self._run_worker, daemon=True).start()

    def _run_worker(self) -> None:
        try:
            payloads = load_payloads(self.fields["payloads"].get())
            parameter = "auto" if self.auto_params.get() else self.fields["param"].get()
            config = FuzzConfig(self.fields["url"].get(), parameter, self.method.get(), self.body.get(), float(self.fields["timeout"].get()), float(self.fields["pause"].get()))
            fuzz_target(config, payloads, on_recon=lambda profile: self.root.after(0, self._update_recon, profile), on_result=lambda result: self.root.after(0, self._update_result, result))
            self.root.after(0, lambda: (self.header_badge.configure(text="●  COMPLETE", bg="#193C2B", fg=COLORS["success"]), self._set_status("Ejecución completada · revisa los indicadores")))
        except (ValueError, OSError, ReconError) as exc:
            self.root.after(0, lambda: (self.header_badge.configure(text="●  BLOCKED", bg="#4A2024", fg=COLORS["danger"]), self._set_status("Ejecución bloqueada: valida el target y la configuración", tone="danger"), self._write(f"[BLOCKED] {exc}\n", "error"), messagebox.showerror("Ejecución bloqueada", str(exc))))


def launch() -> None:
    """Launch the GUI; kept as the public entrypoint for CLI and legacy callers."""
    root = tk.Tk()
    FZZApp(root)
    root.mainloop()


__all__ = ["FZZApp", "launch"]
