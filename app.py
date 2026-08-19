from __future__ import annotations

import inspect
import math
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
    APP_VERSION,
    ExportOptions,
    ScanOptions,
    dedupe_entity_replacements,
    export_sanitized,
    preview_page,
    scan_document,
    suggest_output_path,
)


class PIIScrubberApp(tk.Tk):
    """Fast claimant-identity scrubber for SSD/medical PDFs.

    Deliberately narrow policy:
    - scrub claimant name variants, claimant surname occurrences, claimant DOB,
      claimant SSN, claimant home address, and document metadata;
    - preserve MRNs, provider names, provider/lab/facility addresses, treatment
      dates, URLs, and unrelated medical-record content.
    """

    SCRUB_CATEGORIES = {
        "SSN",
        "SOCIAL SECURITY NUMBER",
        "DOB",
        "DATE OF BIRTH",
        "BIRTH DATE",
        "CLAIMANT NAME",
        "PATIENT NAME",
    }

    NEVER_SCRUB_CATEGORIES = {
        "MRN",
        "MEDICAL RECORD NUMBER",
        "MEDICAL RECORD #",
        "URL",
        "PROVIDER NAME",
        "PHONE",
        "FAX",
        "EMAIL",
        "IPV4",
        "ZIP",
    }

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
        self.identity_values = set()
        self.claimant_addresses = set()
        self._build()
        self.after(100, self._poll)
        self.after(500, self._tick_elapsed)

    def _build(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        ttk.Label(
            top,
            text=f"Local PII Scrubber v{APP_VERSION}",
            font=("Segoe UI", 18, "bold"),
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            top,
            text=(
                "Fast Claimant PII Mode — scrubs claimant identity + metadata only; "
                "MRNs, providers, labs, treatment dates, and unrelated addresses are preserved."
            ),
        ).grid(row=1, column=0, columnspan=7, sticky="w", pady=(2, 8))

        self.path_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.path_var).grid(
            row=2, column=0, columnspan=5, sticky="ew", padx=(0, 6)
        )
        ttk.Button(top, text="Open PDF", command=self.open_pdf).grid(row=2, column=5, padx=3)
        ttk.Button(top, text="Scan", command=self.scan).grid(row=2, column=6, padx=3)
        top.columnconfigure(0, weight=1)

        policy = ttk.Frame(top)
        policy.grid(row=3, column=0, columnspan=7, sticky="ew", pady=(8, 0))
        ttk.Label(policy, text="Policy: Claimant PII Only", font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Label(
            policy,
            text="  •  existing OCR first  •  selective OCR fallback  •  metadata sanitized  •  no broad de-identification",
        ).pack(side="left")

        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=10, pady=6)
        left = ttk.Frame(body)
        right = ttk.Frame(body)
        body.add(left, weight=3)
        body.add(right, weight=2)

        cols = ("page", "category", "source", "confidence", "action", "value")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        labels = {
            "page": "Page",
            "category": "Category",
            "source": "Source",
            "confidence": "Conf.",
            "action": "Automatic action",
            "value": "Detected value",
        }
        widths = {
            "page": 58,
            "category": 135,
            "source": 70,
            "confidence": 60,
            "action": 150,
            "value": 330,
        }
        for col in cols:
            self.tree.heading(col, text=labels[col])
            self.tree.column(col, width=widths[col], anchor="w")
        ybar = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ybar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ybar.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        ttk.Label(right, text="Preview", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        self.canvas = tk.Canvas(right, bg="#666666", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

        export = ttk.LabelFrame(self, text="Verified Export", padding=8)
        export.pack(fill="x", padx=10, pady=(2, 6))
        ttk.Label(
            export,
            text="Automatic: claimant identity is scrubbed; unrelated medical-record information is preserved.",
        ).pack(side="left")
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
        # Large chunks reduce overhead on searchable 1,000+ page PDFs.
        kwargs = dict(
            chunk_size=500,
            selective_ocr=not identity_only,
            detect_names=not identity_only,
            detect_addresses=not identity_only,
            custom_terms=list(custom_terms or []),
        )
        if "fast_ocr_pdf" in inspect.signature(ScanOptions).parameters:
            kwargs["fast_ocr_pdf"] = True
        return ScanOptions(**kwargs)

    def _export_options(self):
        kwargs = dict(
            chunk_size=500,
            mode="tokens",
            sanitize=True,  # removes PDF metadata/XMP and other supported hidden document data
            selective_rasterize_on_failure=True,
            restore_search_on_rasterized_pages=False,  # fastest safe fallback; avoids a second OCR pass
        )
        if "fast_ocr_pdf" in inspect.signature(ExportOptions).parameters:
            kwargs["fast_ocr_pdf"] = True
        return ExportOptions(**kwargs)

    @staticmethod
    def _normalize(value):
        return " ".join(str(value or "").strip().split())

    @staticmethod
    def _rect_center(finding):
        rect = getattr(finding, "rect", getattr(finding, "bbox", None))
        if rect is None:
            return None
        try:
            if hasattr(rect, "x0"):
                return ((float(rect.x0) + float(rect.x1)) / 2.0, (float(rect.y0) + float(rect.y1)) / 2.0)
            if len(rect) >= 4:
                return ((float(rect[0]) + float(rect[2])) / 2.0, (float(rect[1]) + float(rect[3])) / 2.0)
        except Exception:
            return None
        return None

    @staticmethod
    def _address_variants(value):
        text = PIIScrubberApp._normalize(value)
        if len(text) < 6:
            return set()
        variants = {text, re.sub(r"[,.#]", " ", text)}
        replacements = [
            (r"\bSOUTH\b", "S"),
            (r"\bNORTH\b", "N"),
            (r"\bEAST\b", "E"),
            (r"\bWEST\b", "W"),
            (r"\bSTREET\b", "ST"),
            (r"\bAVENUE\b", "AVE"),
            (r"\bROAD\b", "RD"),
            (r"\bDRIVE\b", "DR"),
            (r"\bBOULEVARD\b", "BLVD"),
            (r"\bLANE\b", "LN"),
            (r"\bCOURT\b", "CT"),
            (r"\bAPARTMENT\b", "APT"),
        ]
        upper = text.upper()
        for pattern, short in replacements:
            variants.add(re.sub(pattern, short, upper))
        return {PIIScrubberApp._normalize(v) for v in variants if len(PIIScrubberApp._normalize(v)) >= 6}

    def _claimant_name_findings(self, findings):
        return [
            f
            for f in findings
            if str(getattr(f, "category", "")).strip().upper() in {"CLAIMANT NAME", "PATIENT NAME"}
        ]

    def _claimant_address_values(self, findings):
        """Choose only addresses spatially associated with a claimant/patient name.

        Generic addresses are preserved. This prevents lab/provider/facility addresses
        from being scrubbed merely because they are addresses.
        """
        names = self._claimant_name_findings(findings)
        addresses = [
            f
            for f in findings
            if str(getattr(f, "category", "")).strip().upper() == "ADDRESS"
        ]
        selected = set()

        for name in names:
            same_page = [a for a in addresses if getattr(a, "page", None) == getattr(name, "page", None)]
            if not same_page:
                continue
            ncenter = self._rect_center(name)
            if ncenter is None:
                # Without coordinates, do not guess. Preserving an unrelated address is safer
                # than broadly removing every institutional address.
                continue

            ranked = []
            for addr in same_page:
                acenter = self._rect_center(addr)
                if acenter is None:
                    continue
                distance = math.hypot(acenter[0] - ncenter[0], acenter[1] - ncenter[1])
                # Claimant demographic/header blocks are normally close together.
                if distance <= 260:
                    ranked.append((distance, addr))
            if ranked:
                ranked.sort(key=lambda item: item[0])
                selected.add(self._normalize(ranked[0][1].value))

        return {v for v in selected if v}

    def _identity_terms(self, findings):
        terms = set()
        claimant_names = self._claimant_name_findings(findings)

        for finding in claimant_names:
            value = self._normalize(finding.value)
            if not value:
                continue
            terms.add(value)
            parts = [p for p in re.findall(r"[A-Za-z][A-Za-z'\-]+", value) if len(p) >= 2]
            if parts:
                # Full first name and surname are scrubbed everywhere. Surname matching also
                # removes any other person who has the claimant's last name, per user policy.
                terms.add(parts[0])
                terms.add(parts[-1])

        self.claimant_addresses = self._claimant_address_values(findings)
        for address in self.claimant_addresses:
            terms.update(self._address_variants(address))

        self.identity_values = {self._normalize(t).casefold() for t in terms if self._normalize(t)}
        return sorted(terms, key=len, reverse=True)

    @staticmethod
    def _finding_key(finding):
        rect = getattr(finding, "rect", getattr(finding, "bbox", None))
        return (
            getattr(finding, "page", None),
            str(getattr(finding, "value", "")).casefold(),
            repr(rect),
        )

    def _apply_narrow_policy(self):
        for finding in self.findings:
            category = str(getattr(finding, "category", "")).strip().upper()
            value_key = self._normalize(getattr(finding, "value", "")).casefold()

            # Default is PRESERVE. Only explicitly required claimant PII is selected.
            selected = False

            if category in self.SCRUB_CATEGORIES:
                selected = True
            elif category in self.NEVER_SCRUB_CATEGORIES:
                selected = False
            elif category == "ADDRESS":
                selected = value_key in {a.casefold() for a in self.claimant_addresses}
            elif value_key and value_key in self.identity_values:
                # Findings from the exact claimant-identity pass (first name, surname,
                # full name, claimant-address variants) are scrubbed regardless of the
                # engine's generic category label.
                selected = True

            finding.selected = selected

        dedupe_entity_replacements(self.findings)

    def checkpoint_path(self, suffix=""):
        if not self.input_path:
            return ""
        p = Path(self.input_path)
        # New policy gets its own checkpoint namespace so stale broad-policy results
        # cannot be resumed into this build.
        return str(p.parent / ("." + p.name + f".pii-claimant-only-v1{suffix}.checkpoint"))

    def open_pdf(self):
        p = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if p:
            self.input_path = p
            self.path_var.set(p)
            self.findings = []
            self.page_modes = {}
            self.identity_values = set()
            self.claimant_addresses = set()
            self._refresh_tree()
            self.status_var.set("PDF loaded. Click Scan.")

    def _progress_cb(self, stage, current, total):
        self.q.put(("progress", stage, current, total))

    def _identity_progress_cb(self, stage, current, total):
        total = max(1, total)
        pct = 88.0 + (max(0, min(current, total)) / total) * 12.0
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
        except Exception as exc:
            self._finish_operation()
            self.status_var.set("Scan could not start.")
            messagebox.showerror(
                "PII Scrubber - Scan Error",
                f"The scan could not start.\n\n{type(exc).__name__}: {exc}",
            )

    def _scan_worker(self):
        try:
            self.q.put(("status", "Primary scan — existing searchable text first..."))
            findings, modes = scan_document(
                self.input_path,
                self._scan_options(),
                self.checkpoint_path(),
                self._progress_cb,
            )

            terms = self._identity_terms(findings)
            if terms:
                self.q.put(("status", f"Fast claimant identity check: {len(terms)} exact variants..."))
                extra, _ = scan_document(
                    self.input_path,
                    self._scan_options(terms, identity_only=True),
                    self.checkpoint_path("-identity"),
                    self._identity_progress_cb,
                )
                seen = {self._finding_key(f) for f in findings}
                for finding in extra:
                    key = self._finding_key(finding)
                    if key not in seen:
                        findings.append(finding)
                        seen.add(key)

            self.q.put(("scan_done", findings, modes))
        except Exception as exc:
            self.q.put(("error", f"Scan failed: {type(exc).__name__}: {exc}"))

    def _refresh_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for idx, finding in enumerate(self.findings):
            value = str(finding.value)
            if str(finding.category).strip().upper() == "SSN":
                digits = "".join(ch for ch in value if ch.isdigit())
                value = "***-**-" + digits[-4:]
            action = "SCRUB" if finding.selected else "PRESERVE"
            self.tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(
                    finding.page,
                    finding.category,
                    finding.source,
                    f"{finding.confidence:.2f}",
                    action,
                    value,
                ),
            )

    def on_select(self, event=None):
        selection = self.tree.selection()
        if not selection or not self.input_path:
            return
        finding = self.findings[int(selection[0])]
        try:
            data = preview_page(self.input_path, finding.page, self.findings)
            image = Image.open(BytesIO(data))
            image.thumbnail(
                (
                    max(300, self.canvas.winfo_width() - 20),
                    max(300, self.canvas.winfo_height() - 20),
                )
            )
            self.preview_img = ImageTk.PhotoImage(image)
            self.canvas.delete("all")
            self.canvas.create_image(10, 10, image=self.preview_img, anchor="nw")
        except Exception as exc:
            self.status_var.set(f"Preview unavailable: {exc}")

    def export(self):
        try:
            if not self.input_path or not self.findings:
                messagebox.showerror("PII Scrubber", "Scan the PDF first.")
                return

            suggested = suggest_output_path(self.input_path)
            output_path = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                initialfile=Path(suggested).name,
                filetypes=[("PDF files", "*.pdf")],
            )
            if not output_path:
                return
            if os.path.abspath(output_path) == os.path.abspath(self.input_path):
                messagebox.showerror("PII Scrubber", "The scrubbed file cannot overwrite the original.")
                return

            self._start_operation("Scrubbing claimant PII, sanitizing metadata, and verifying...")
            threading.Thread(
                target=self._export_worker,
                args=(output_path, self._export_options()),
                daemon=True,
            ).start()
        except Exception as exc:
            self._finish_operation()
            self.status_var.set("Export could not start.")
            messagebox.showerror(
                "PII Scrubber - Export Error",
                f"The export could not start.\n\n{type(exc).__name__}: {exc}",
            )

    def _export_worker(self, output_path, options):
        try:
            result = export_sanitized(
                self.input_path,
                output_path,
                self.findings,
                self.page_modes,
                options,
                self._progress_cb,
            )
            self.q.put(("export_done", result))
        except Exception as exc:
            self.q.put(("error", f"Export failed: {type(exc).__name__}: {exc}"))

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
                    # Reserve the final 12% for the lightweight identity check.
                    pct = min(88.0, (current / total) * 88.0)
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
                    self._apply_narrow_policy()
                    self._finish_operation()
                    self.progress["value"] = 100
                    self.progress_var.set("100%")
                    self._refresh_tree()
                    scrub_count = sum(1 for f in self.findings if f.selected)
                    preserve_count = len(self.findings) - scrub_count
                    failed_ocr = sum(1 for mode in self.page_modes.values() if mode == "ocr_failed")
                    self.status_var.set(
                        f"Scan complete: {scrub_count} claimant-PII findings to scrub; "
                        f"{preserve_count} other findings preserved. OCR review pages: {failed_ocr}."
                    )

                elif msg[0] == "export_done":
                    self._finish_operation()
                    self.progress["value"] = 100
                    self.progress_var.set("100%")
                    result = msg[1]
                    review_pages = result["audit"]["pages_requiring_review"]
                    document_review = result["audit"].get("document_review_required", False)
                    if review_pages or document_review:
                        self.status_var.set(f"Export created; review required. Page flags: {len(review_pages)}.")
                        messagebox.showwarning(
                            "Review required",
                            f"Export created, but automated verification did not receive a clean document-level PASS.\n\n"
                            f"Page flags: {len(review_pages)}\nPDF: {result['output_path']}\nAudit: {result['audit_path']}",
                        )
                    else:
                        self.status_var.set("Verified export complete.")
                        messagebox.showinfo(
                            "Scrubbing Complete",
                            f"Sanitized PDF created successfully.\n\n"
                            f"Claimant PII verification: PASSED\nMetadata sanitization: COMPLETED\n"
                            f"Pages requiring review: 0\n\nPDF: {result['output_path']}\nAudit: {result['audit_path']}",
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
