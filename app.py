from __future__ import annotations

import inspect
import os
import queue
import re
import threading
import time
import tkinter as tk
from io import BytesIO
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageTk

from engine import (
    APP_VERSION, ExportOptions, ScanOptions, dedupe_entity_replacements,
    export_sanitized, preview_page, scan_document, suggest_output_path,
)


class PIIScrubberApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Local PII Scrubber v{APP_VERSION}")
        self.geometry("1320x820")
        self.minsize(1100, 700)
        self.input_path = ""
        self.findings = []
        self.page_modes = {}
        self.preview_img = None
        self.q = queue.Queue()
        self.operation_start = None
        self.operation_active = False
        self._build()
        self.after(100, self._poll)
        self.after(500, self._tick_elapsed)

    def _build(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text=f"Local PII Scrubber v{APP_VERSION}", font=("Segoe UI", 18, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(top, text="Automatic SSD / Medical Mode — optimized for large searchable/OCR PDFs; treatment dates and provider names preserved.").grid(row=1, column=0, columnspan=7, sticky="w", pady=(2, 8))
        self.path_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.path_var).grid(row=2, column=0, columnspan=5, sticky="ew", padx=(0, 6))
        ttk.Button(top, text="Open PDF", command=self.open_pdf).grid(row=2, column=5, padx=3)
        ttk.Button(top, text="Scan", command=self.scan).grid(row=2, column=6, padx=3)
        top.columnconfigure(0, weight=1)

        policy = ttk.Frame(top)
        policy.grid(row=3, column=0, columnspan=7, sticky="ew", pady=(8, 0))
        ttk.Label(policy, text="Policy: SSD / Medical", font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Label(policy, text="  •  existing OCR first  •  selective OCR fallback  •  fast claimant identity check  •  failed-page rasterization only").pack(side="left")

        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=10, pady=6)
        left = ttk.Frame(body)
        right = ttk.Frame(body)
        body.add(left, weight=3)
        body.add(right, weight=2)

        cols = ("page", "category", "source", "confidence", "action", "value")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        labels = {
            "page": "Page", "category": "Category", "source": "Source",
            "confidence": "Conf.", "action": "Automatic action", "value": "Detected value",
        }
        widths = {"page": 58, "category": 125, "source": 70, "confidence": 60, "action": 150, "value": 330}
        for c in cols:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w")
        y = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=y.set)
        self.tree.pack(side="left", fill="both", expand=True)
        y.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        ttk.Label(right, text="Preview", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        self.canvas = tk.Canvas(right, bg="#666666", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

        export = ttk.LabelFrame(self, text="Verified Export", padding=8)
        export.pack(fill="x", padx=10, pady=(2, 6))
        ttk.Label(export, text="Automatic policy: claimant identifiers scrubbed; provider names and public URLs preserved.").pack(side="left")
        ttk.Button(export, text="Scrub + Verify + Export", command=self.export).pack(side="right")

        status = ttk.Frame(self, padding=(10, 0, 10, 10))
        status.pack(fill="x")
        self.progress = ttk.Progressbar(status, mode="determinate", maximum=100)
        self.progress.pack(fill="x")
        info = ttk.Frame(status)
        info.pack(fill="x", pady=(3, 0))
        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.StringVar(value="0%")
        self.elapsed_var = tk.StringVar(value="Elapsed: 00:00")
        ttk.Label(info, textvariable=self.status_var).pack(side="left", anchor="w")
        ttk.Label(info, textvariable=self.progress_var).pack(side="right", padx=(12, 0))
        ttk.Label(info, textvariable=self.elapsed_var).pack(side="right")

    def _start_operation(self, message):
        self.operation_start = time.monotonic()
        self.operation_active = True
        self.progress["maximum"] = 100
        self.progress["value"] = 0
        self.progress_var.set("0%")
        self.elapsed_var.set("Elapsed: 00:00")
        self.status_var.set(message)
        self.update_idletasks()

    def _finish_operation(self):
        self.operation_active = False
        if self.operation_start is not None:
            elapsed = int(time.monotonic() - self.operation_start)
            self.elapsed_var.set(f"Elapsed: {elapsed // 60:02d}:{elapsed % 60:02d}")

    def _tick_elapsed(self):
        if self.operation_active and self.operation_start is not None:
            elapsed = int(time.monotonic() - self.operation_start)
            self.elapsed_var.set(f"Elapsed: {elapsed // 60:02d}:{elapsed % 60:02d}")
        self.after(500, self._tick_elapsed)

    def _scan_options(self, custom_terms=None, identity_only=False):
        if identity_only:
            kwargs = dict(
                chunk_size=500,
                selective_ocr=False,
                detect_names=False,
                detect_addresses=False,
                custom_terms=list(custom_terms or []),
            )
        else:
            kwargs = dict(
                chunk_size=250,
                selective_ocr=True,
                detect_names=True,
                detect_addresses=True,
                custom_terms=list(custom_terms or []),
            )
        if "fast_ocr_pdf" in inspect.signature(ScanOptions).parameters:
            kwargs["fast_ocr_pdf"] = True
        return ScanOptions(**kwargs)

    def _export_options(self):
        kwargs = dict(
            chunk_size=250,
            mode="tokens",
            sanitize=True,
            selective_rasterize_on_failure=True,
            restore_search_on_rasterized_pages=True,
        )
        if "fast_ocr_pdf" in inspect.signature(ExportOptions).parameters:
            kwargs["fast_ocr_pdf"] = True
        return ExportOptions(**kwargs)

    @staticmethod
    def _address_variants(value):
        text = " ".join(str(value).strip().split())
        if len(text) < 6:
            return set()
        variants = {text, re.sub(r"[,.#]", " ", text)}
        swaps = [
            (r"\bSOUTH\b", "S"), (r"\bNORTH\b", "N"), (r"\bEAST\b", "E"), (r"\bWEST\b", "W"),
            (r"\bSTREET\b", "ST"), (r"\bAVENUE\b", "AVE"), (r"\bROAD\b", "RD"), (r"\bDRIVE\b", "DR"),
            (r"\bBOULEVARD\b", "BLVD"), (r"\bLANE\b", "LN"), (r"\bCOURT\b", "CT"), (r"\bSUITE\b", "STE"),
        ]
        upper = text.upper()
        for pattern, short in swaps:
            variants.add(re.sub(pattern, short, upper))
        return {" ".join(v.split()) for v in variants if len(" ".join(v.split())) >= 6}

    def _identity_terms(self, findings):
        terms = set()
        provider_names = {
            str(f.value).strip().upper()
            for f in findings
            if str(f.category).strip().upper() == "PROVIDER NAME"
        }
        provider_parts = {
            part
            for name in provider_names
            for part in re.findall(r"[A-Z][A-Z'\-]+", name)
            if len(part) >= 3
        }
        for f in findings:
            category = str(f.category).strip().upper()
            value = " ".join(str(f.value).strip().split())
            if category in {"CLAIMANT NAME", "PATIENT NAME"} and value:
                terms.add(value)
                parts = [p for p in re.findall(r"[A-Za-z][A-Za-z'\-]+", value) if len(p) >= 3]
                for part in parts:
                    if part.upper() not in provider_parts:
                        terms.add(part)
            elif category == "ADDRESS" and value:
                terms.update(self._address_variants(value))
        return sorted(terms, key=len, reverse=True)

    @staticmethod
    def _finding_key(f):
        rect = getattr(f, "rect", getattr(f, "bbox", None))
        return (getattr(f, "page", None), str(getattr(f, "value", "")).casefold(), repr(rect))

    def _apply_ssd_medical_policy(self):
        preserve = {"URL", "PROVIDER NAME"}
        for f in self.findings:
            f.selected = str(f.category).strip().upper() not in preserve
        dedupe_entity_replacements(self.findings)

    def checkpoint_path(self, suffix=""):
        if not self.input_path:
            return ""
        p = Path(self.input_path)
        return str(p.parent / ("." + p.name + f".pii-v3{suffix}.checkpoint"))

    def open_pdf(self):
        p = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if p:
            self.input_path = p
            self.path_var.set(p)
            self.findings = []
            self.page_modes = {}
            self._refresh_tree()
            self.status_var.set("PDF loaded. Click Scan.")

    def _progress_cb(self, stage, current, total):
        self.q.put(("progress", stage, current, total))

    def _identity_progress_cb(self, stage, current, total):
        # Keep the progress bar moving forward instead of appearing to restart after the primary scan.
        total = max(1, total)
        pct = 85.0 + (max(0, min(current, total)) / total) * 15.0
        self.q.put(("progress_absolute", "Fast claimant identity check", pct, current, total))

    def scan(self):
        try:
            p = self.path_var.get().strip()
            if not p or not os.path.exists(p):
                messagebox.showerror("PII Scrubber", "Choose a PDF first.")
                return
            if not p.lower().endswith(".pdf"):
                messagebox.showerror("PII Scrubber", "The selected file is not a PDF.")
                return
            self.input_path = p
            self._start_operation("Scanning existing OCR text...")
            threading.Thread(target=self._scan_worker, daemon=True).start()
        except Exception as e:
            self._finish_operation()
            self.status_var.set("Scan could not start.")
            messagebox.showerror("PII Scrubber - Scan Error", f"The scan could not start.\n\n{type(e).__name__}: {e}")

    def _scan_worker(self):
        try:
            self.q.put(("status", "Primary PII scan — existing OCR text first..."))
            findings, modes = scan_document(
                self.input_path,
                self._scan_options(),
                self.checkpoint_path(),
                self._progress_cb,
            )

            terms = self._identity_terms(findings)
            if terms:
                self.q.put(("status", f"Fast claimant identity check: {len(terms)} variants..."))
                extra, _ = scan_document(
                    self.input_path,
                    self._scan_options(terms, identity_only=True),
                    self.checkpoint_path("-identity-fast"),
                    self._identity_progress_cb,
                )
                seen = {self._finding_key(f) for f in findings}
                for f in extra:
                    key = self._finding_key(f)
                    if key not in seen:
                        findings.append(f)
                        seen.add(key)

            self.q.put(("scan_done", findings, modes))
        except Exception as e:
            self.q.put(("error", f"Scan failed: {type(e).__name__}: {e}"))

    def _refresh_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for idx, f in enumerate(self.findings):
            display = f.value if f.category != "SSN" else "***-**-" + "".join(ch for ch in f.value if ch.isdigit())[-4:]
            action = "SCRUB" if f.selected else "PRESERVE"
            self.tree.insert("", "end", iid=str(idx), values=(f.page, f.category, f.source, f"{f.confidence:.2f}", action, display))

    def on_select(self, event=None):
        sel = self.tree.selection()
        if not sel or not self.input_path:
            return
        idx = int(sel[0])
        f = self.findings[idx]
        try:
            data = preview_page(self.input_path, f.page, self.findings)
            im = Image.open(BytesIO(data))
            im.thumbnail((max(300, self.canvas.winfo_width() - 20), max(300, self.canvas.winfo_height() - 20)))
            self.preview_img = ImageTk.PhotoImage(im)
            self.canvas.delete("all")
            self.canvas.create_image(10, 10, image=self.preview_img, anchor="nw")
        except Exception as e:
            self.status_var.set(f"Preview unavailable: {e}")

    def export(self):
        try:
            if not self.input_path or not self.findings:
                messagebox.showerror("PII Scrubber", "Scan the PDF first.")
                return
            suggested = suggest_output_path(self.input_path)
            out = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                initialfile=Path(suggested).name,
                filetypes=[("PDF files", "*.pdf")],
            )
            if not out:
                return
            if os.path.abspath(out) == os.path.abspath(self.input_path):
                messagebox.showerror("PII Scrubber", "The scrubbed file cannot overwrite the original.")
                return
            opts = self._export_options()
            self._start_operation("Scrubbing, sanitizing, and verifying...")
            threading.Thread(target=self._export_worker, args=(out, opts), daemon=True).start()
        except Exception as e:
            self._finish_operation()
            self.status_var.set("Export could not start.")
            messagebox.showerror("PII Scrubber - Export Error", f"The export could not start.\n\n{type(e).__name__}: {e}")

    def _export_worker(self, out, opts):
        try:
            self.q.put(("export_done", export_sanitized(self.input_path, out, self.findings, self.page_modes, opts, self._progress_cb)))
        except Exception as e:
            self.q.put(("error", f"Export failed: {type(e).__name__}: {e}"))

    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                if msg[0] == "status":
                    self.status_var.set(msg[1])
                elif msg[0] == "progress":
                    _, stage, current, total = msg
                    total = max(1, total)
                    current = max(0, min(current, total))
                    # Reserve the final 15% for the lightweight claimant-identity pass.
                    pct = min(85.0, (current / total) * 85.0)
                    self.progress["value"] = pct
                    self.progress_var.set(f"{pct:5.1f}%")
                    self.status_var.set(f"{stage.replace('_', ' ').title()}: {current}/{total}")
                elif msg[0] == "progress_absolute":
                    _, stage, pct, current, total = msg
                    self.progress["value"] = pct
                    self.progress_var.set(f"{pct:5.1f}%")
                    self.status_var.set(f"{stage}: {current}/{total}")
                elif msg[0] == "scan_done":
                    _, self.findings, self.page_modes = msg
                    self._apply_ssd_medical_policy()
                    self._finish_operation()
                    self.progress["value"] = 100
                    self.progress_var.set("100%")
                    self._refresh_tree()
                    failed_ocr = sum(1 for m in self.page_modes.values() if m == "ocr_failed")
                    scrub_count = sum(1 for f in self.findings if f.selected)
                    preserve_count = len(self.findings) - scrub_count
                    self.status_var.set(f"Scan complete: {scrub_count} to scrub, {preserve_count} preserved. OCR review pages: {failed_ocr}.")
                elif msg[0] == "export_done":
                    self._finish_operation()
                    self.progress["value"] = 100
                    self.progress_var.set("100%")
                    result = msg[1]
                    review = result["audit"]["pages_requiring_review"]
                    doc_review = result["audit"].get("document_review_required", False)
                    if review or doc_review:
                        self.status_var.set(f"Export created; review required. Page flags: {len(review)}.")
                        messagebox.showwarning(
                            "Review required",
                            f"Export created, but automated verification did not receive a clean document-level PASS.\n\nPage flags: {len(review)}\nPDF: {result['output_path']}\nAudit: {result['audit_path']}",
                        )
                    else:
                        self.status_var.set("Verified export complete.")
                        messagebox.showinfo(
                            "Scrubbing Complete",
                            f"Sanitized PDF created successfully.\n\nAutomated verification: PASSED\nPages requiring review: 0\n\nPDF: {result['output_path']}\nAudit: {result['audit_path']}",
                        )
                elif msg[0] == "error":
                    self._finish_operation()
                    self.status_var.set(msg[1])
                    messagebox.showerror("PII Scrubber", msg[1])
        except queue.Empty:
            pass
        self.after(100, self._poll)


if __name__ == "__main__":
    PIIScrubberApp().mainloop()
