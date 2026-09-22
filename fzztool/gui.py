"""Optional Tkinter interface for the same CLI services."""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .fuzzer import FuzzConfig, FuzzResult, fuzz_target
from .recon import ReconProfile
from .payloads import default_payload_file, load_payloads


def launch() -> None:
    root = tk.Tk()
    root.title("FZZ — pruebas autorizadas")
    root.geometry("820x560")
    fields: dict[str, tk.StringVar] = {}
    defaults = {"url": "http://localhost:3000/", "param": "q", "payloads": str(default_payload_file()), "timeout": "10", "pause": "0.5"}
    form = ttk.Frame(root, padding=12)
    form.pack(fill="x")
    for row, (key, label) in enumerate((("url", "URL"), ("param", "Parámetro"), ("payloads", "Payload YAML"), ("timeout", "Timeout (s)"), ("pause", "Pausa (s)"))):
        ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", padx=4, pady=4)
        fields[key] = tk.StringVar(value=defaults[key])
        ttk.Entry(form, textvariable=fields[key], width=78).grid(row=row, column=1, sticky="ew", padx=4, pady=4)
    form.columnconfigure(1, weight=1)
    method = tk.StringVar(value="GET")
    body = tk.StringVar(value="form")
    ttk.Label(form, text="Método").grid(row=5, column=0, sticky="w", padx=4, pady=4)
    ttk.Combobox(form, textvariable=method, values=("GET", "POST"), state="readonly", width=10).grid(row=5, column=1, sticky="w", padx=4)
    ttk.Label(form, text="Body POST").grid(row=6, column=0, sticky="w", padx=4, pady=4)
    ttk.Combobox(form, textvariable=body, values=("form", "json"), state="readonly", width=10).grid(row=6, column=1, sticky="w", padx=4)
    output = tk.Text(root, height=20, wrap="word")
    output.pack(fill="both", expand=True, padx=12, pady=8)
    def append(result: FuzzResult) -> None:
        output.after(0, lambda: output.insert("end", f"{result.status_code or 'ERROR'} {result.elapsed:.2f}s {result.category}/{result.technique}: {result.payload}\n" + ("  [!] " + "; ".join(result.indicators) + "\n" if result.indicators else "")))
    def append_recon(profile: ReconProfile) -> None:
        output.after(0, lambda: output.insert("end", f"Reconocimiento validado: {profile.status_code} {profile.final_url} | {profile.title or 'sin título'} | {profile.content_type or 'tipo desconocido'}\n"))
    def run() -> None:
        try:
            payloads = load_payloads(fields["payloads"].get())
            config = FuzzConfig(fields["url"].get(), fields["param"].get(), method.get(), body.get(), float(fields["timeout"].get()), float(fields["pause"].get()))
            output.delete("1.0", "end")
            fuzz_target(config, payloads, on_result=append, on_recon=append_recon)
        except (ValueError, OSError) as exc:
            output.after(0, lambda: messagebox.showerror("Configuración", str(exc)))
    ttk.Button(root, text="Ejecutar fuzzing autorizado", command=lambda: threading.Thread(target=run, daemon=True).start()).pack(pady=(0, 12))
    root.mainloop()
