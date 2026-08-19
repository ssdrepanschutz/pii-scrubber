from __future__ import annotations

import inspect
import math
import os
import queue
import re
import threading
import time
import tkinter as tk
from collections import Counter
from io import BytesIO
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageTk

from engine import (
    APP_VERSION as ENGINE_VERSION,
    ExportOptions,
    ScanOptions,
    dedupe_entity_replacements,
    export_sanitized,
    preview_page,
    scan_document,
)


UI_BUILD = "3.2.1"
POLICY_VERSION = "claimant-only-v3"


class PIIScrubberApp(tk.Tk):
    """Fast, narrow claimant-PII scrubber for SSD/medical PDFs."""

    SCRUB_CATEGORIES = {
        "SSN",
        "SOCIAL SECURITY NUMBER",
        "DOB",
        "DATE OF BIRTH",
        "BIRTH DATE",
    }

    NEVER_SCRUB_CATEGORIES = {
        "MRN",
        "MRN/ACCOUNT",
        "MRN / ACCOUNT",
        "MEDICAL RECORD NUMBER",
        "MEDICAL RECORD #",
        "ACCOUNT",
        "ACCOUNT NUMBER",
        "PATIENT ID",
        "URL",
        "PROVIDER NAME",
        "PHONE",
        "FAX",
        "EMAIL",
        "IPV4",
        "ZIP",
    }

    GENERIC_NAME_LABELS = {
        "patient",
        "patient name",
        "claimant",
        "claimant name",
        "member",
        "member name",
        "beneficiary",
        "beneficiary name",
        "applicant",
        "applicant name",
        "insured",
        "insured name",
        "name",
    }

    NAME_CATEGORIES = {"CLAIMANT NAME", "PATIENT NAME"}
    NAME_SUFFIXES = {"jr", "sr", "ii", "iii", "iv", "v"}
    PROVIDER_CREDENTIALS = {"md", "do", "np", "pa", "rn", "phd", "lcsw", "psyd", "dpm"}

    def __init__(self):
        super().__init__()
        self.title(f"Local PII Scrubber {UI_BUILD}")
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
        self.accepted_claimant_names = set()
        self._build()
        self.after(100, self._poll)
        self.after(500, self._tick_elapsed)

    def _build(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        ttk.Label(
            top,
            text=f"Local PII Scrubber {UI_BUILD}",
            font=("Segoe UI", 18, "bold"),
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            top,
            text=(
                f"Claimant PII Only — build {UI_BUILD} / engine {ENGINE_VERSION}. "
                "Scrubs claimant identity + metadata; preserves unrelated medical-record content."
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
            text=(
                "  •  SSN / DOB  •  claimant name + first name + surname  •  claimant home address  "
                "•  metadata  •  everything else preserved"
            ),
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
            "value": "PII to remove",
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
            text="Only the claimant-PII findings shown above are sent to the scrub/export engine.",
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
        kwargs = dict(
            chunk_size=500 if identity_only else 250,
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
            chunk_size=250,
            mode="tokens",
            sanitize=True,
            selective_rasterize_on_failure=True,
            restore_search_on_rasterized_pages=False,
        )
        if "fast_ocr_pdf" in inspect.signature(ExportOptions).parameters:
            kwargs["fast_ocr_pdf"] = True
        return ExportOptions(**kwargs)

    @staticmethod
    def _normalize(value):
        return " ".join(str(value or "").strip().split())

    @classmethod
    def _clean_name(cls, value):
        text = cls._normalize(value)
        if not text:
            return ""
        text = re.sub(
            r"^(?:patient|claimant|member|beneficiary|applicant|insured)\s*(?:name)?\s*[:#\-]?\s*",
            "",
            text,
            flags=re.IGNORECASE,
        )
        return cls._normalize(text)

    @classmethod
    def _is_plausible_person_name(cls, value):
        text = cls._clean_name(value)
        if not text or text.casefold() in cls.GENERIC_NAME_LABELS:
            return False
        if any(ch.isdigit() for ch in text):
            return False
        tokens = re.findall(r"[A-Za-z][A-Za-z'\-.]*", text)
        if len(tokens) < 2:
            return False
        lower_tokens = {t.strip(".").casefold() for t in tokens}
        if lower_tokens & cls.PROVIDER_CREDENTIALS:
            return False
        return True

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

    def _provider_name_values(self, findings):
        return {
            self._normalize(getattr(f, "value", "")).casefold()
            for f in findings
            if str(getattr(f, "category", "")).strip().upper() == "PROVIDER NAME"
        }

    def _claimant_name_findings(self, findings):
        providers = self._provider_name_values(findings)
        accepted = []
        self.accepted_claimant_names = set()
        for finding in findings:
            category = str(getattr(finding, "category", "")).strip().upper()
            if category not in self.NAME_CATEGORIES:
                continue
            cleaned = self._clean_name(getattr(finding, "value", ""))
            if not self._is_plausible_person_name(cleaned):
                continue
            if cleaned.casefold() in providers:
                continue
            accepted.append(finding)
            self.accepted_claimant_names.add(cleaned.casefold())
        return accepted

    def _nearby_dob_anchor(self, name_finding, findings):
        ncenter = self._rect_center(name_finding)
        if ncenter is None:
            return False
        for finding in findings:
            if getattr(finding, "page", None) != getattr(name_finding, "page", None):
                continue
            category = str(getattr(finding, "category", "")).strip().upper()
            if category not in {"DOB", "DATE OF BIRTH", "BIRTH DATE"}:
                continue
            center = self._rect_center(finding)
            if center is not None and math.hypot(center[0] - ncenter[0], center[1] - ncenter[1]) <= 280:
                return True
        return False

    def _claimant_address_values(self, findings, claimant_names):
        addresses = [
            f for f in findings
            if str(getattr(f, "category", "")).strip().upper() == "ADDRESS"
        ]
        providers = [
            f for f in findings
            if str(getattr(f, "category", "")).strip().upper() == "PROVIDER NAME"
        ]
        candidates = []

        for name in claimant_names:
            ncenter = self._rect_center(name)
            if ncenter is None:
                continue
            has_dob_anchor = self._nearby_dob_anchor(name, findings)
            for addr in addresses:
                if getattr(addr, "page", None) != getattr(name, "page", None):
                    continue
                acenter = self._rect_center(addr)
                if acenter is None:
                    continue

                dx = abs(acenter[0] - ncenter[0])
                dy = acenter[1] - ncenter[1]
                if dx > 140 or dy < -25 or dy > 185:
                    continue

                name_distance = math.hypot(acenter[0] - ncenter[0], acenter[1] - ncenter[1])
                provider_closer = False
                for provider in providers:
                    if getattr(provider, "page", None) != getattr(addr, "page", None):
                        continue
                    pcenter = self._rect_center(provider)
                    if pcenter is None:
                        continue
                    if math.hypot(acenter[0] - pcenter[0], acenter[1] - pcenter[1]) < name_distance:
                        provider_closer = True
                        break
                if provider_closer:
                    continue

                candidates.append((self._normalize(addr.value), has_dob_anchor))

        counts = Counter(value.casefold() for value, _ in candidates if value)
        selected = set()
        for value, has_dob_anchor in candidates:
            if value and (has_dob_anchor or counts[value.casefold()] >= 2):
                selected.add(value)
        return selected

    @classmethod
    def _name_parts(cls, cleaned_name):
        text = cls._clean_name(cleaned_name)
        if not text:
            return set()

        if "," in text:
            left, right = text.split(",", 1)
            surname_tokens = re.findall(r"[A-Za-z][A-Za-z'\-.]*", left)
            first_tokens = re.findall(r"[A-Za-z][A-Za-z'\-.]*", right)
            surname = surname_tokens[-1] if surname_tokens else ""
            first = first_tokens[0] if first_tokens else ""
        else:
            tokens = re.findall(r"[A-Za-z][A-Za-z'\-.]*", text)
            while tokens and tokens[-1].strip(".").casefold() in cls.NAME_SUFFIXES:
                tokens.pop()
            first = tokens[0] if tokens else ""
            surname = tokens[-1] if len(tokens) >= 2 else ""

        return {part for part in (first, surname) if len(part.strip(".")) >= 2}

    def _identity_terms(self, findings):
        terms = set()
        claimant_names = self._claimant_name_findings(findings)

        for finding in claimant_names:
            cleaned = self._clean_name(getattr(finding, "value", ""))
            if not cleaned:
                continue
            terms.add(cleaned)
            terms.update(self._name_parts(cleaned))

        self.claimant_addresses = self._claimant_address_values(findings, claimant_names)
        for address in self.claimant_addresses:
            terms.update(self._address_variants(address))

        self.identity_values = {
            self._normalize(term).casefold()
            for term in terms
            if self._normalize(term).casefold() not in self.GENERIC_NAME_LABELS
        }
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
        claimant_address_keys = {a.casefold() for a in self.claimant_addresses}

        for finding in self.findings:
            category = str(getattr(finding, "category", "")).strip().upper()
            value = self._normalize(getattr(finding, "value", ""))
            value_key = value.casefold()
            selected = False

            # Explicit preserve rules win. MRNs and other non-target identifiers never
            # reach the export engine even if the detector found them.
            if category in self.NEVER_SCRUB_CATEGORIES:
                selected = False
            elif value_key in self.GENERIC_NAME_LABELS:
                selected = False
            elif category in self.SCRUB_CATEGORIES:
                selected = True
            elif category == "ADDRESS":
                selected = value_key in claimant_address_keys
            elif value_key and value_key in self.identity_values:
                selected = True

            finding.selected = selected

        scrub_findings = [f for f in self.findings if f.selected]
        dedupe_entity_replacements(scrub_findings)

    def _scrub_findings(self):
        return [f for f in self.findings if getattr(f, "selected", False)]

    def checkpoint_path(self, suffix=""):
        if not self.input_path:
            return ""
        p = Path(self.input_path)
        return str(p.parent / ("." + p.name + f".{POLICY_VERSION}{suffix}.checkpoint"))

    def open_pdf(self):
        p = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if p:
            self.input_path = p
            self.path_var.set(p)
            self.findings = []
            self.page_modes = {}
            self.identity_values = set()
            self.claimant_addresses = set()
            self.accepted_claimant_names = set()
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

        # Do not load preserved MRNs, provider names, URLs, lab addresses, etc. into
        # the interface. There is nothing for the user to decide about them.
        for idx, finding in enumerate(self.findings):
            if not getattr(finding, "selected", False):
                continue
            value = str(finding.value)
            if str(finding.category).strip().upper() == "SSN":
                digits = "".join(ch for ch in value if ch.isdigit())
                value = "***-**-" + digits[-4:]
            self.tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(
                    finding.page,
                    finding.category,
                    finding.source,
                    f"{finding.confidence:.2f}",
                    "SCRUB",
                    value,
                ),
            )

    def on_select(self, event=None):
        selection = self.tree.selection()
        if not selection or not self.input_path:
            return
        finding = self.findings[int(selection[0])]
        try:
            data = preview_page(self.input_path, finding.page, self._scrub_findings())
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
            scrub_findings = self._scrub_findings()
            if not self.input_path or not scrub_findings:
                messagebox.showerror("PII Scrubber", "Scan the PDF first. No claimant PII findings are currently selected for removal.")
                return

            output_path = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                initialfile="PII-Scrubbed.pdf",
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
                args=(output_path, scrub_findings, self._export_options()),
                daemon=True,
            ).start()
        except Exception as exc:
            self._finish_operation()
            self.status_var.set("Export could not start.")
            messagebox.showerror(
                "PII Scrubber - Export Error",
                f"The export could not start.\n\n{type(exc).__name__}: {exc}",
            )

    def _export_worker(self, output_path, scrub_findings, options):
        try:
            result = export_sanitized(
                self.input_path,
                output_path,
                scrub_findings,
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
                    scrub_count = len(self._scrub_findings())
                    ignored_count = len(self.findings) - scrub_count
                    failed_ocr = sum(1 for mode in self.page_modes.values() if mode == "ocr_failed")
                    self.status_var.set(
                        f"Scan complete: {scrub_count} claimant-PII findings to remove; "
                        f"{ignored_count} non-target findings ignored. OCR review pages: {failed_ocr}."
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
