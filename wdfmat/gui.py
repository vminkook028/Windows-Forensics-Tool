from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
import json
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .cli import run_case


class ForensicsDashboard(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Windows Digital Forensics and Malware Assessment")
        self.geometry("1060x720")
        self.minsize(900, 620)
        self.configure(bg="#eef3f7")
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.case_name = tk.StringVar(value="IR-Case-001")
        self.output_dir = tk.StringVar(value=str(Path("outputs").resolve()))
        self.ioc_path = tk.StringVar(value=str(Path("data/iocs.json").resolve()))
        self.rules_dir = tk.StringVar(value=str(Path("rules").resolve()))
        self.vt_enabled = tk.BooleanVar(value=False)
        self.vt_api_key = tk.StringVar(value=os.environ.get("VT_API_KEY", ""))
        self.analyst_name = tk.StringVar(value=os.environ.get("USERNAME", ""))
        self.case_notes = tk.StringVar(value="")
        self.clock_text = tk.StringVar(value="")
        self.scan_started_at = ""
        self._build_styles()
        self._build_layout()
        self._tick_clock()
        self.after(250, self._poll_events)

    def _build_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#eef3f7")
        style.configure("Panel.TFrame", background="#ffffff", relief="flat")
        style.configure("TLabel", background="#eef3f7", foreground="#17202a", font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background="#ffffff", foreground="#17202a", font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#102033", foreground="#ffffff", font=("Segoe UI", 18, "bold"))
        style.configure("Subtitle.TLabel", background="#102033", foreground="#c8d4df", font=("Segoe UI", 10))
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
        style.configure("Treeview", rowheight=26, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_layout(self) -> None:
        header = tk.Frame(self, bg="#102033", height=86)
        header.pack(fill="x")
        ttk.Label(header, text="Windows Digital Forensics and Malware Assessment", style="Title.TLabel").pack(anchor="w", padx=24, pady=(18, 2))
        ttk.Label(header, text="Case-centric collection, malware triage, timeline, and reporting", style="Subtitle.TLabel").pack(anchor="w", padx=24)
        ttk.Label(header, textvariable=self.clock_text, style="Subtitle.TLabel").place(relx=1.0, x=-24, y=22, anchor="ne")

        main = ttk.Frame(self)
        main.pack(fill="both", expand=True, padx=18, pady=18)
        main.columnconfigure(0, weight=0, minsize=330)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(0, weight=1)

        left = ttk.Frame(main, style="Panel.TFrame", padding=16)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        right = ttk.Frame(main, style="Panel.TFrame", padding=12)
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        self._form(left)
        self._results(right)

    def _form(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Case Settings", style="Panel.TLabel", font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=(0, 12))
        self._entry(parent, "Case Name", self.case_name)
        self._entry(parent, "Analyst Name", self.analyst_name)
        self._entry(parent, "Case Notes", self.case_notes)
        self._path_entry(parent, "Output Folder", self.output_dir, folder=True)
        self._path_entry(parent, "IOC JSON", self.ioc_path, folder=False)
        self._path_entry(parent, "YARA Rules Folder", self.rules_dir, folder=True)
        ttk.Checkbutton(parent, text="Enable VirusTotal reputation lookups", variable=self.vt_enabled).pack(anchor="w", pady=(14, 6))
        self._entry(parent, "VirusTotal API Key", self.vt_api_key, show="*")
        ttk.Separator(parent).pack(fill="x", pady=18)
        self.run_btn = ttk.Button(parent, text="Start Forensic Scan", style="Accent.TButton", command=self._start_scan)
        self.run_btn.pack(fill="x", ipady=8)
        ttk.Button(parent, text="Open Output Folder", command=self._open_output).pack(fill="x", pady=(10, 0), ipady=6)
        self.progress = ttk.Progressbar(parent, mode="indeterminate")
        self.progress.pack(fill="x", pady=(18, 6))
        self.status = ttk.Label(parent, text="Ready. Run as Administrator for best coverage.", style="Panel.TLabel", wraplength=290)
        self.status.pack(anchor="w", pady=(8, 0))

    def _entry(self, parent: ttk.Frame, label: str, var: tk.StringVar, show: str | None = None) -> None:
        ttk.Label(parent, text=label, style="Panel.TLabel").pack(anchor="w", pady=(8, 3))
        ttk.Entry(parent, textvariable=var, show=show).pack(fill="x", ipady=4)

    def _path_entry(self, parent: ttk.Frame, label: str, var: tk.StringVar, folder: bool) -> None:
        ttk.Label(parent, text=label, style="Panel.TLabel").pack(anchor="w", pady=(8, 3))
        row = ttk.Frame(parent, style="Panel.TFrame")
        row.pack(fill="x")
        row.columnconfigure(0, weight=1)
        ttk.Entry(row, textvariable=var).grid(row=0, column=0, sticky="ew", ipady=4)
        ttk.Button(row, text="Browse", command=lambda: self._browse(var, folder)).grid(row=0, column=1, padx=(8, 0))

    def _results(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Assessment Dashboard", style="Panel.TLabel", font=("Segoe UI", 13, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 10))
        notebook = ttk.Notebook(parent)
        notebook.grid(row=1, column=0, sticky="nsew")
        self.summary = tk.Text(notebook, height=10, wrap="word", font=("Segoe UI", 10), relief="flat", padx=12, pady=12)
        self.findings = ttk.Treeview(notebook, columns=("risk", "category", "title"), show="headings")
        for col, width in [("risk", 90), ("category", 160), ("title", 440)]:
            self.findings.heading(col, text=col.title())
            self.findings.column(col, width=width, anchor="w")
        self.logs = tk.Text(notebook, wrap="word", font=("Consolas", 9), relief="flat", padx=12, pady=12)
        notebook.add(self.summary, text="Summary")
        notebook.add(self.findings, text="Findings")
        notebook.add(self.logs, text="Run Log")
        self.summary.insert("end", "No scan has been run yet.\n")
        self.summary.configure(state="disabled")
        self.logs.configure(state="disabled")

    def _browse(self, var: tk.StringVar, folder: bool) -> None:
        value = filedialog.askdirectory() if folder else filedialog.askopenfilename(filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if value:
            var.set(value)

    def _open_output(self) -> None:
        path = Path(self.output_dir.get())
        path.mkdir(parents=True, exist_ok=True)
        os.startfile(path)

    def _start_scan(self) -> None:
        self.run_btn.configure(state="disabled")
        self.progress.start(12)
        self.scan_started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._log(f"Starting forensic collection at {self.scan_started_at}...")
        self.status.configure(text="Scanning. This can take several minutes on busy systems.")
        args = (
            self.case_name.get().strip() or "forensic_case",
            Path(self.output_dir.get()),
            Path(self.ioc_path.get()),
            Path(self.rules_dir.get()),
            self.vt_enabled.get(),
            self.vt_api_key.get().strip(),
            self.analyst_name.get().strip(),
            self.case_notes.get().strip(),
        )
        threading.Thread(target=self._worker, args=args, daemon=True).start()

    def _worker(self, *args: object) -> None:
        try:
            paths = run_case(*args)  # type: ignore[arg-type]
            self.events.put(("done", paths))
        except Exception as exc:
            self.events.put(("error", exc))

    def _poll_events(self) -> None:
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event == "done":
                    self.progress.stop()
                    self.run_btn.configure(state="normal")
                    self.status.configure(text="Scan complete. Reports are ready.")
                    self._render_done(payload)  # type: ignore[arg-type]
                elif event == "error":
                    self.progress.stop()
                    self.run_btn.configure(state="normal")
                    self.status.configure(text="Scan failed. See run log.")
                    self._log(f"ERROR: {payload}")
                    messagebox.showerror("Scan failed", str(payload))
        except queue.Empty:
            pass
        self.after(250, self._poll_events)

    def _render_done(self, paths: dict[str, Path]) -> None:
        self._log("Reports generated:")
        for kind, path in paths.items():
            self._log(f"  {kind}: {path}")
        case_data = self._load_case(paths.get("json"))
        for item in self.findings.get_children():
            self.findings.delete(item)
        for finding in case_data.get("findings", []):
            self.findings.insert("", "end", values=(finding.get("risk", ""), finding.get("category", ""), finding.get("title", "")))
        self.summary.configure(state="normal")
        self.summary.delete("1.0", "end")
        self.summary.insert("end", "Scan complete.\n\n")
        if case_data:
            self.summary.insert("end", f"Host: {case_data.get('host', '')}\n")
            self.summary.insert("end", f"Analyst: {case_data.get('metadata', {}).get('analyst', '')}\n")
            self.summary.insert("end", f"Started: {case_data.get('started_at', '')}\n")
            self.summary.insert("end", f"Completed: {case_data.get('completed_at', '')}\n")
            self.summary.insert("end", f"Duration: {case_data.get('metadata', {}).get('duration_seconds', 0)} seconds\n")
            self.summary.insert("end", f"Findings: {len(case_data.get('findings', []))}\n")
            self.summary.insert("end", f"Timeline events: {len(case_data.get('timeline', []))}\n\n")
        for kind, path in paths.items():
            self.summary.insert("end", f"{kind.upper()} report: {path}\n")
        self.summary.insert("end", "\nOpen the HTML report for the richest analyst view.\n")
        self.summary.configure(state="disabled")

    def _load_case(self, path: Path | None) -> dict[str, object]:
        if not path or not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            self._log(f"Could not load JSON summary: {exc}")
            return {}

    def _tick_clock(self) -> None:
        self.clock_text.set(datetime.now().strftime("%d-%m-%Y %H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _log(self, line: str) -> None:
        self.logs.configure(state="normal")
        self.logs.insert("end", line + "\n")
        self.logs.see("end")
        self.logs.configure(state="disabled")


def main() -> None:
    app = ForensicsDashboard()
    app.mainloop()
