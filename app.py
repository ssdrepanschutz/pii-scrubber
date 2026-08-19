from __future__ import annotations

import csv
import inspect
import io
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import fitz
from PIL import Image, ImageDraw, ImageTk


APP_VERSION = "4.0.0"
DISCOVERY_PAGES = 60
NATIVE_TEXT_MIN_CHARS = 20
OCR_DPI = 144

SSN_ANCHORED_RE = re.compile(
    r"(?i)\b(?:SSN|SOCIAL\s+SECURITY\s+(?:NUMBER|NO\.?))\b\s*[:#]?\s*"
    r"([0-9]{3}\s*[- ]?\s*[0-9]{2}\s*[- ]?\s*[0-9]{4})"
)
DOB_ANCHORED_RE = re.compile(
    r"(?i)\b(?:DOB|DATE\s+OF\s+BIRTH|BIRTH\s+DATE|BORN)\b\s*[:#]?\s*"
    r"((?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4})|(?:\d{4}-\d{1,2}-\d{1,2}))"
)
GENERIC_NAME_WORDS = {
    "patient", "claimant", "member", "beneficiary", "applicant", "insured",
    "name", "reported", "report", "date", "employer", "employee", "provider",
}
STOP_AFTER_NAME = re.compile(
    r"(?i)\s+(?:DOB|SSN|DATE\s+HIRED|EMPLOYER|ADDRESS|SEX|GENDER|AGE|REPORT(?:ED)?|WAGES|EIN|PHONE|FAX)\b.*$"
)
ADDRESS_EXCLUDE = re.compile(r"(?i)\b(?:EMPLOYER|PROVIDER|LAB|LABORATORY|FACILITY|CLINIC|HOSPITAL|OFFICE)\b")
ADDRESS_LABEL = re.compile(r"(?i)\b(?:HOME|MAILING|RESIDENCE|STREET)\s+ADDRESS\b\s*[:#-]?\s*(.*)$")
GENERIC_ADDRESS_LABEL = re.compile(r"(?i)(?<!EMPLOYER\s)(?<!PROVIDER\s)\bADDRESS\b\s*[:#-]\s*(.*)$")


@dataclass(frozen=True)
class WordBox:
    text: str
    rect: tuple[float, float, float, float]
    block: int
    line: int
    word: int
    source: str = "native"


@dataclass
class Finding:
    page: int
    category: str
    value: str
    rect: tuple[float, float, float, float]
    source: str
    confidence: float = 1.0


class PIIScrubberApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Local PII Scrubber {APP_VERSION}")
        self.geometry("1320x820")
        self.minsize(1100, 700)
        self.input_path = ""
        self.findings: list[Finding] = []
        self.preview_img = None
        self.q: queue.Queue = queue.Queue()
        self.operation_start = None
        self.operation_active = False
        self.identity: dict[str, object] = {}
        self.ocr_pages: set[int] = set()
        self._build()
        self.after(100, self._poll)
        self.after(500, self._tick_elapsed)

    def _build(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text=f"Local PII Scrubber {APP_VERSION}", font=("Segoe UI", 18, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(
            top,
            text="Claimant Identity Only — no general PII detector. Existing OCR first; metadata removed automatically.",
        ).grid(row=1, column=0, columnspan=7, sticky="w", pady=(2, 8))

        self.path_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.path_var).grid(row=2, column=0, columnspan=5, sticky="ew", padx=(0, 6))
        ttk.Button(top, text="Open PDF", command=self.open_pdf).grid(row=2, column=5, padx=3)
        ttk.Button(top, text="Scan", command=self.scan).grid(row=2, column=6, padx=3)
        top.columnconfigure(0, weight=1)

        policy = ttk.Frame(top)
        policy.grid(row=3, column=0, columnspan=7, sticky="ew", pady=(8, 0))
        ttk.Label(policy, text="Removes:", font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Label(policy, text=" claimant first name • claimant surname everywhere • SSN • DOB in birth context • claimant home address • PDF metadata").pack(side="left")

        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=10, pady=6)
        left = ttk.Frame(body)
        right = ttk.Frame(body)
        body.add(left, weight=3)
        body.add(right, weight=2)

        cols = ("page", "category", "source", "action", "value")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        labels = {"page": "Page", "category": "Category", "source": "Source", "action": "Action", "value": "Detected target"}
        widths = {"page": 60, "category": 160, "source": 80, "action": 90, "value": 420}
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
        ttk.Label(export, text="Only the targets shown above are redacted. MRNs, EINs, employers, providers, labs, and unrelated addresses are ignored.").pack(side="left")
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

    def _start_operation(self, message: str):
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

    def open_pdf(self):
        path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if path:
            self.input_path = path
            self.path_var.set(path)
            self.findings = []
            self.identity = {}
            self.ocr_pages = set()
            self._refresh_tree()
            self.status_var.set("PDF loaded. Click Scan.")

    @staticmethod
    def _app_root() -> Path:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent
        return Path(__file__).resolve().parent

    def _tesseract_exe(self) -> str | None:
        candidates = [
            self._app_root() / "Tesseract-OCR" / "tesseract.exe",
            Path(getattr(sys, "_MEIPASS", self._app_root())) / "Tesseract-OCR" / "tesseract.exe",
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return shutil.which("tesseract")

    @staticmethod
    def _native_words(page: fitz.Page) -> list[WordBox]:
        out: list[WordBox] = []
        for item in page.get_text("words", sort=True):
            if len(item) < 5:
                continue
            text = str(item[4]).strip()
            if not text:
                continue
            block = int(item[5]) if len(item) > 5 else 0
            line = int(item[6]) if len(item) > 6 else 0
            word = int(item[7]) if len(item) > 7 else len(out)
            out.append(WordBox(text, (float(item[0]), float(item[1]), float(item[2]), float(item[3])), block, line, word, "native"))
        return out

    def _ocr_words(self, page: fitz.Page) -> list[WordBox]:
        tess = self._tesseract_exe()
        if not tess:
            return []
        scale = OCR_DPI / 72.0
        pix = page.get_pixmap(matrix=fitz.Matrix(scale, scale), alpha=False)
        with tempfile.TemporaryDirectory(prefix="pii-ocr-") as td:
            image_path = Path(td) / "page.png"
            pix.save(str(image_path))
            cmd = [tess, str(image_path), "stdout", "-l", "eng", "--psm", "6", "tsv"]
            tessdata = Path(tess).parent / "tessdata"
            if tessdata.exists():
                cmd[3:3] = ["--tessdata-dir", str(tessdata)]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if proc.returncode != 0:
                return []
            reader = csv.DictReader(io.StringIO(proc.stdout), delimiter="\t")
            sx = page.rect.width / max(1, pix.width)
            sy = page.rect.height / max(1, pix.height)
            out: list[WordBox] = []
            for row in reader:
                text = (row.get("text") or "").strip()
                if not text:
                    continue
                try:
                    conf = float(row.get("conf") or -1)
                    if conf < 20:
                        continue
                    left = float(row.get("left") or 0)
                    top = float(row.get("top") or 0)
                    width = float(row.get("width") or 0)
                    height = float(row.get("height") or 0)
                    block = int(row.get("block_num") or 0)
                    line = int(row.get("line_num") or 0)
                    word = int(row.get("word_num") or len(out))
                except ValueError:
                    continue
                out.append(WordBox(text, (left * sx, top * sy, (left + width) * sx, (top + height) * sy), block, line, word, "ocr"))
            return out

    def _page_words(self, page: fitz.Page, page_number: int, allow_ocr: bool = True) -> list[WordBox]:
        words = self._native_words(page)
        char_count = sum(len(w.text) for w in words)
        if char_count >= NATIVE_TEXT_MIN_CHARS or not allow_ocr:
            return words
        ocr = self._ocr_words(page)
        if ocr:
            self.ocr_pages.add(page_number)
            return ocr
        return words

    @staticmethod
    def _line_groups(words: list[WordBox]) -> list[list[WordBox]]:
        grouped: dict[tuple[int, int], list[WordBox]] = defaultdict(list)
        for word in words:
            grouped[(word.block, word.line)].append(word)
        lines = []
        for key in sorted(grouped):
            lines.append(sorted(grouped[key], key=lambda w: (w.rect[0], w.word)))
        return lines

    @staticmethod
    def _line_text(line: list[WordBox]) -> str:
        return " ".join(w.text for w in line).strip()

    @staticmethod
    def _joined(words: list[WordBox]) -> tuple[str, list[tuple[int, int, int]]]:
        ordered = sorted(words, key=lambda w: (w.block, w.line, w.word, w.rect[0]))
        parts: list[str] = []
        spans: list[tuple[int, int, int]] = []
        cursor = 0
        for idx, word in enumerate(ordered):
            if parts:
                parts.append(" ")
                cursor += 1
            start = cursor
            parts.append(word.text)
            cursor += len(word.text)
            spans.append((start, cursor, idx))
        return "".join(parts), spans

    @staticmethod
    def _union_rect(words: list[WordBox]) -> tuple[float, float, float, float]:
        return (
            min(w.rect[0] for w in words),
            min(w.rect[1] for w in words),
            max(w.rect[2] for w in words),
            max(w.rect[3] for w in words),
        )

    @staticmethod
    def _match_rect(words: list[WordBox], spans: list[tuple[int, int, int]], start: int, end: int) -> tuple[float, float, float, float] | None:
        ordered = sorted(words, key=lambda w: (w.block, w.line, w.word, w.rect[0]))
        hits = [ordered[idx] for s, e, idx in spans if e > start and s < end]
        if not hits:
            return None
        return PIIScrubberApp._union_rect(hits)

    @staticmethod
    def _digits(value: str) -> str:
        return "".join(ch for ch in value if ch.isdigit())

    @staticmethod
    def _normalize_name(value: str) -> str:
        value = STOP_AFTER_NAME.sub("", value)
        value = re.sub(r"[^A-Za-z'\-., ]+", " ", value)
        value = re.sub(r"\s+", " ", value).strip(" ,.-")
        tokens = value.split()
        while tokens and tokens[-1].upper().strip(".") in {"M", "F", "U", "X"}:
            tokens.pop()
        return " ".join(tokens).strip()

    @staticmethod
    def _plausible_name(value: str) -> bool:
        if not value:
            return False
        tokens = re.findall(r"[A-Za-z][A-Za-z'\-.]*", value)
        if len(tokens) < 2 or len(tokens) > 6:
            return False
        lowered = {t.strip(".").casefold() for t in tokens}
        if lowered <= GENERIC_NAME_WORDS:
            return False
        if lowered & {"md", "do", "rn", "np", "pa", "phd", "lcsw", "psyd"}:
            return False
        return True

    def _name_candidates(self, words: list[WordBox], page_text: str) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        has_anchor = bool(SSN_ANCHORED_RE.search(page_text) or DOB_ANCHORED_RE.search(page_text))
        patterns = [
            (re.compile(r"(?i)\bNAME\s*\(\s*F\s*,?\s*M\s*,?\s*I\s*,?\s*L\s*\)\s*[:#-]?\s*(.+)$"), 8),
            (re.compile(r"(?i)\b(?:CLAIMANT|PATIENT|BENEFICIARY|APPLICANT)\s+NAME\s*[:#-]?\s*(.+)$"), 7),
            (re.compile(r"(?i)^\s*NAME\s*[:#-]\s*(.+)$"), 3 if has_anchor else 0),
        ]
        for line in self._line_groups(words):
            text = self._line_text(line)
            if re.search(r"(?i)\b(?:REPORTED|EMPLOYER|PROVIDER)\s+NAME\b", text):
                continue
            for pattern, base_score in patterns:
                if base_score <= 0:
                    continue
                match = pattern.search(text)
                if not match:
                    continue
                candidate = self._normalize_name(match.group(1))
                if self._plausible_name(candidate):
                    out.append((candidate, base_score + (4 if has_anchor else 0)))
        return out

    @staticmethod
    def _parse_date(value: str) -> tuple[int, int, int] | None:
        raw = value.strip()
        formats = ["%m/%d/%Y", "%m-%d-%Y", "%m/%d/%y", "%m-%d-%y", "%Y-%m-%d"]
        for fmt in formats:
            try:
                dt = datetime.strptime(raw, fmt)
                if 1900 <= dt.year <= datetime.now().year:
                    return dt.year, dt.month, dt.day
            except ValueError:
                pass
        return None

    def _discover_identity(self, doc: fitz.Document) -> tuple[dict[str, object], dict[int, list[WordBox]]]:
        limit = min(DISCOVERY_PAGES, doc.page_count)
        cache: dict[int, list[WordBox]] = {}
        name_scores: Counter[str] = Counter()
        name_original: dict[str, str] = {}
        ssn_scores: Counter[str] = Counter()
        dob_scores: Counter[tuple[int, int, int]] = Counter()

        for idx in range(limit):
            page = doc.load_page(idx)
            words = self._page_words(page, idx + 1, allow_ocr=True)
            cache[idx] = words
            joined, _ = self._joined(words)
            for candidate, score in self._name_candidates(words, joined):
                key = candidate.casefold()
                name_scores[key] += score
                name_original.setdefault(key, candidate)
            for match in SSN_ANCHORED_RE.finditer(joined):
                digits = self._digits(match.group(1))
                if len(digits) == 9:
                    ssn_scores[digits] += 1
            for match in DOB_ANCHORED_RE.finditer(joined):
                parsed = self._parse_date(match.group(1))
                if parsed:
                    dob_scores[parsed] += 1
            self.q.put(("progress", "Identity discovery", idx + 1, max(1, limit), 0, 20))

        if not name_scores and limit < doc.page_count:
            for idx in range(limit, doc.page_count):
                page = doc.load_page(idx)
                words = self._page_words(page, idx + 1, allow_ocr=False)
                joined, _ = self._joined(words)
                for candidate, score in self._name_candidates(words, joined):
                    key = candidate.casefold()
                    name_scores[key] += score
                    name_original.setdefault(key, candidate)
                for match in SSN_ANCHORED_RE.finditer(joined):
                    digits = self._digits(match.group(1))
                    if len(digits) == 9:
                        ssn_scores[digits] += 1
                for match in DOB_ANCHORED_RE.finditer(joined):
                    parsed = self._parse_date(match.group(1))
                    if parsed:
                        dob_scores[parsed] += 1
                if name_scores and max(name_scores.values()) >= 7:
                    break

        identity: dict[str, object] = {}
        if name_scores:
            best_key, _ = name_scores.most_common(1)[0]
            name = name_original[best_key]
            identity["name"] = name
            tokens = re.findall(r"[A-Za-z][A-Za-z'\-.]*", name)
            if "," in name:
                left, right = name.split(",", 1)
                left_tokens = re.findall(r"[A-Za-z][A-Za-z'\-.]*", left)
                right_tokens = re.findall(r"[A-Za-z][A-Za-z'\-.]*", right)
                if left_tokens:
                    identity["surname"] = left_tokens[-1].strip(".")
                if right_tokens and len(right_tokens[0].strip(".")) >= 2:
                    identity["first"] = right_tokens[0].strip(".")
            elif len(tokens) >= 2:
                identity["surname"] = tokens[-1].strip(".")
                if len(tokens[0].strip(".")) >= 2:
                    identity["first"] = tokens[0].strip(".")
        if ssn_scores:
            identity["ssn"] = ssn_scores.most_common(1)[0][0]
        if dob_scores:
            identity["dob"] = dob_scores.most_common(1)[0][0]

        address = self._discover_address(cache, identity)
        if address:
            identity["address"] = address
        return identity, cache

    def _discover_address(self, cache: dict[int, list[WordBox]], identity: dict[str, object]) -> str | None:
        surname = str(identity.get("surname") or "").casefold()
        ssn = str(identity.get("ssn") or "")
        dob = identity.get("dob")
        candidates: Counter[str] = Counter()
        for words in cache.values():
            joined, _ = self._joined(words)
            page_has_identity = bool(surname and re.search(rf"(?i)\b{re.escape(surname)}\b", joined))
            if ssn and ssn in self._digits(joined):
                page_has_identity = True
            if dob and self._dob_regex(dob).search(joined):
                page_has_identity = True
            lines = self._line_groups(words)
            for i, line in enumerate(lines):
                text = self._line_text(line)
                if ADDRESS_EXCLUDE.search(text):
                    continue
                match = ADDRESS_LABEL.search(text)
                if not match and page_has_identity:
                    match = GENERIC_ADDRESS_LABEL.search(text)
                if not match:
                    continue
                value = match.group(1).strip(" :-")
                if len(value) < 5 and i + 1 < len(lines):
                    value = self._line_text(lines[i + 1]).strip()
                if not re.search(r"\d", value) or len(value) < 6:
                    continue
                candidates[value] += 3 if ADDRESS_LABEL.search(text) else 1
        return candidates.most_common(1)[0][0] if candidates else None

    @staticmethod
    def _ssn_regex(digits: str) -> re.Pattern:
        a, b, c = digits[:3], digits[3:5], digits[5:]
        return re.compile(rf"(?<!\d){a}\s*[- ]?\s*{b}\s*[- ]?\s*{c}(?!\d)")

    @staticmethod
    def _dob_regex(dob: tuple[int, int, int]) -> re.Pattern:
        year, month, day = dob
        yy = str(year)[-2:]
        return re.compile(
            rf"(?<!\d)(?:0?{month}[/-]0?{day}[/-](?:{year}|{yy})|{year}-0?{month}-0?{day})(?!\d)",
            re.I,
        )

    @staticmethod
    def _phrase_regex(value: str) -> re.Pattern | None:
        tokens = re.findall(r"[A-Za-z0-9]+", value)
        if not tokens:
            return None
        return re.compile(r"(?i)" + r"[\s,.'#\-/]+".join(re.escape(t) for t in tokens))

    def _add_matches(self, findings: list[Finding], words: list[WordBox], page_number: int, pattern: re.Pattern, category: str, value: str, context_check=None):
        joined, spans = self._joined(words)
        source = "ocr" if any(w.source == "ocr" for w in words) else "native"
        for match in pattern.finditer(joined):
            if context_check and not context_check(joined, match):
                continue
            rect = self._match_rect(words, spans, match.start(), match.end())
            if rect:
                findings.append(Finding(page_number, category, value, rect, source, 1.0))

    def _scan_targets(self, doc: fitz.Document, identity: dict[str, object], cache: dict[int, list[WordBox]]) -> list[Finding]:
        findings: list[Finding] = []
        surname = str(identity.get("surname") or "")
        first = str(identity.get("first") or "")
        ssn = str(identity.get("ssn") or "")
        dob = identity.get("dob")
        address = str(identity.get("address") or "")

        surname_re = re.compile(rf"(?i)(?<![A-Za-z]){re.escape(surname)}(?![A-Za-z])") if surname else None
        first_re = re.compile(rf"(?i)(?<![A-Za-z]){re.escape(first)}(?![A-Za-z])") if len(first) >= 3 else None
        ssn_re = self._ssn_regex(ssn) if len(ssn) == 9 else None
        dob_re = self._dob_regex(dob) if dob else None
        address_re = self._phrase_regex(address) if address else None

        def dob_context(text: str, match: re.Match) -> bool:
            left = max(0, match.start() - 70)
            right = min(len(text), match.end() + 70)
            context = text[left:right]
            return bool(re.search(r"(?i)\b(?:DOB|DATE\s+OF\s+BIRTH|BIRTH\s+DATE|BORN|SSN)\b", context))

        for idx in range(doc.page_count):
            page_number = idx + 1
            words = cache.get(idx)
            if words is None:
                words = self._page_words(doc.load_page(idx), page_number, allow_ocr=True)
            if surname_re:
                self._add_matches(findings, words, page_number, surname_re, "Claimant Surname", surname)
            if first_re:
                self._add_matches(findings, words, page_number, first_re, "Claimant First Name", first)
            if ssn_re:
                self._add_matches(findings, words, page_number, ssn_re, "SSN", ssn)
            if dob_re:
                self._add_matches(findings, words, page_number, dob_re, "DOB", f"{dob[1]:02d}/{dob[2]:02d}/{dob[0]}", dob_context)
            if address_re:
                self._add_matches(findings, words, page_number, address_re, "Claimant Address", address)
            self.q.put(("progress", "Target scan", page_number, max(1, doc.page_count), 20, 95))

        return self._dedupe_findings(findings)

    @staticmethod
    def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
        out: list[Finding] = []
        seen = set()
        for finding in findings:
            key = (
                finding.page,
                finding.category,
                round(finding.rect[0], 1), round(finding.rect[1], 1),
                round(finding.rect[2], 1), round(finding.rect[3], 1),
            )
            if key not in seen:
                seen.add(key)
                out.append(finding)
        return sorted(out, key=lambda f: (f.page, f.rect[1], f.rect[0], f.category))

    def scan(self):
        path = self.path_var.get().strip()
        if not path or not os.path.exists(path) or not path.lower().endswith(".pdf"):
            messagebox.showerror("PII Scrubber", "Choose a PDF first.")
            return
        self.input_path = path
        self.findings = []
        self.identity = {}
        self.ocr_pages = set()
        self._refresh_tree()
        self._start_operation("Identifying claimant identity...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            with fitz.open(self.input_path) as doc:
                identity, cache = self._discover_identity(doc)
                if not identity.get("surname"):
                    raise RuntimeError("The claimant surname could not be identified confidently. No export will be created from an incomplete identity scan.")
                self.q.put(("identity", identity))
                findings = self._scan_targets(doc, identity, cache)
            self.q.put(("scan_done", findings, identity))
        except Exception as exc:
            self.q.put(("error", f"Scan failed: {type(exc).__name__}: {exc}"))

    def _refresh_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for idx, finding in enumerate(self.findings):
            value = finding.value
            if finding.category == "SSN":
                value = "***-**-" + self._digits(value)[-4:]
            self.tree.insert("", "end", iid=str(idx), values=(finding.page, finding.category, finding.source, "SCRUB", value))

    def on_select(self, event=None):
        selection = self.tree.selection()
        if not selection or not self.input_path:
            return
        finding = self.findings[int(selection[0])]
        try:
            with fitz.open(self.input_path) as doc:
                page = doc.load_page(finding.page - 1)
                page_width = page.rect.width
                page_height = page.rect.height
                pix = page.get_pixmap(matrix=fitz.Matrix(1.35, 1.35), alpha=False)
            image = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
            draw = ImageDraw.Draw(image)
            sx = image.width / page_width
            sy = image.height / page_height
            for item in self.findings:
                if item.page != finding.page:
                    continue
                x0, y0, x1, y1 = item.rect
                draw.rectangle((x0 * sx, y0 * sy, x1 * sx, y1 * sy), outline="red", width=2)
            image.thumbnail((max(300, self.canvas.winfo_width() - 20), max(300, self.canvas.winfo_height() - 20)))
            self.preview_img = ImageTk.PhotoImage(image)
            self.canvas.delete("all")
            self.canvas.create_image(10, 10, image=self.preview_img, anchor="nw")
        except Exception as exc:
            self.status_var.set(f"Preview unavailable: {exc}")

    @staticmethod
    def _sanitize_document(doc: fitz.Document):
        try:
            doc.set_metadata({})
        except Exception:
            pass
        try:
            doc.del_xml_metadata()
        except Exception:
            pass
        if hasattr(doc, "scrub"):
            try:
                params = inspect.signature(doc.scrub).parameters
                desired = {
                    "attached_files": True,
                    "clean_pages": True,
                    "embedded_files": True,
                    "hidden_text": False,
                    "javascript": True,
                    "metadata": True,
                    "redactions": False,
                    "reset_fields": False,
                    "reset_responses": False,
                    "thumbnails": True,
                    "xml_metadata": True,
                }
                kwargs = {k: v for k, v in desired.items() if k in params}
                doc.scrub(**kwargs)
            except Exception:
                pass

    def export(self):
        if not self.input_path or not self.findings:
            messagebox.showerror("PII Scrubber", "Scan the PDF first.")
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
        self._start_operation("Applying redactions and removing metadata...")
        threading.Thread(target=self._export_worker, args=(output_path,), daemon=True).start()

    def _export_worker(self, output_path: str):
        temp_path = str(Path(output_path).with_suffix(".tmp.pdf"))
        try:
            by_page: dict[int, list[Finding]] = defaultdict(list)
            for finding in self.findings:
                by_page[finding.page].append(finding)
            with fitz.open(self.input_path) as doc:
                total_pages = max(1, len(by_page))
                for count, page_number in enumerate(sorted(by_page), start=1):
                    page = doc.load_page(page_number - 1)
                    for finding in by_page[page_number]:
                        page.add_redact_annot(fitz.Rect(*finding.rect), fill=(0, 0, 0))
                    page.apply_redactions()
                    self.q.put(("progress", "Redacting", count, total_pages, 0, 55))
                self._sanitize_document(doc)
                doc.save(temp_path, garbage=4, deflate=True, clean=True)
            os.replace(temp_path, output_path)
            audit = self._verify_output(output_path)
            audit_path = str(Path(output_path).with_suffix(".audit.json"))
            with open(audit_path, "w", encoding="utf-8") as handle:
                json.dump(audit, handle, indent=2)
            self.q.put(("export_done", output_path, audit_path, audit))
        except Exception as exc:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except OSError:
                pass
            self.q.put(("error", f"Export failed: {type(exc).__name__}: {exc}"))

    def _verification_patterns(self):
        patterns: list[tuple[str, re.Pattern, object]] = []
        surname = str(self.identity.get("surname") or "")
        first = str(self.identity.get("first") or "")
        ssn = str(self.identity.get("ssn") or "")
        dob = self.identity.get("dob")
        address = str(self.identity.get("address") or "")
        if surname:
            patterns.append(("Claimant Surname", re.compile(rf"(?i)(?<![A-Za-z]){re.escape(surname)}(?![A-Za-z])"), None))
        if len(first) >= 3:
            patterns.append(("Claimant First Name", re.compile(rf"(?i)(?<![A-Za-z]){re.escape(first)}(?![A-Za-z])"), None))
        if len(ssn) == 9:
            patterns.append(("SSN", self._ssn_regex(ssn), None))
        if dob:
            patterns.append(("DOB", self._dob_regex(dob), "dob_context"))
        if address:
            pattern = self._phrase_regex(address)
            if pattern:
                patterns.append(("Claimant Address", pattern, None))
        return patterns

    def _verify_output(self, output_path: str) -> dict:
        failures: list[dict[str, object]] = []
        metadata_clean = True
        patterns = self._verification_patterns()
        with fitz.open(output_path) as doc:
            metadata = doc.metadata or {}
            metadata_clean = not any(str(v or "").strip() for v in metadata.values())
            try:
                xml = doc.get_xml_metadata()
                if str(xml or "").strip():
                    metadata_clean = False
            except Exception:
                pass
            for idx in range(doc.page_count):
                page_number = idx + 1
                text = doc.load_page(idx).get_text("text") or ""
                for category, pattern, check in patterns:
                    for match in pattern.finditer(text):
                        if check == "dob_context":
                            left = max(0, match.start() - 70)
                            right = min(len(text), match.end() + 70)
                            if not re.search(r"(?i)\b(?:DOB|DATE\s+OF\s+BIRTH|BIRTH\s+DATE|BORN|SSN)\b", text[left:right]):
                                continue
                        failures.append({"page": page_number, "category": category})
                        break
                self.q.put(("progress", "Verifying", page_number, max(1, doc.page_count), 55, 100))

        if self.ocr_pages and self._tesseract_exe():
            with fitz.open(output_path) as doc:
                for page_number in sorted(self.ocr_pages):
                    if page_number < 1 or page_number > doc.page_count:
                        continue
                    words = self._ocr_words(doc.load_page(page_number - 1))
                    joined, _ = self._joined(words)
                    for category, pattern, check in patterns:
                        for match in pattern.finditer(joined):
                            if check == "dob_context":
                                left = max(0, match.start() - 70)
                                right = min(len(joined), match.end() + 70)
                                if not re.search(r"(?i)\b(?:DOB|DATE\s+OF\s+BIRTH|BIRTH\s+DATE|BORN|SSN)\b", joined[left:right]):
                                    continue
                            failures.append({"page": page_number, "category": category})
                            break

        counts = Counter(f.category for f in self.findings)
        return {
            "app_version": APP_VERSION,
            "verification_passed": not failures and metadata_clean,
            "metadata_clean": metadata_clean,
            "pages_requiring_review": sorted({int(item["page"]) for item in failures}),
            "failure_categories": sorted({str(item["category"]) for item in failures}),
            "redaction_counts": dict(sorted(counts.items())),
            "ocr_pages_used": len(self.ocr_pages),
            "policy": "claimant identity only",
        }

    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    _, stage, current, total, start_pct, end_pct = msg
                    total = max(1, total)
                    pct = start_pct + (max(0, min(current, total)) / total) * (end_pct - start_pct)
                    self.progress["value"] = pct
                    self.progress_var.set(f"{pct:5.1f}%")
                    self.status_var.set(f"{stage}: {current}/{total}")
                elif kind == "identity":
                    self.identity = msg[1]
                    parts = []
                    if self.identity.get("surname"):
                        parts.append("claimant surname identified")
                    if self.identity.get("ssn"):
                        parts.append("SSN identified")
                    if self.identity.get("dob"):
                        parts.append("DOB identified")
                    if self.identity.get("address"):
                        parts.append("home address identified")
                    self.status_var.set("; ".join(parts) or "Identity discovery complete")
                elif kind == "scan_done":
                    _, self.findings, self.identity = msg
                    self._finish_operation()
                    self.progress["value"] = 100
                    self.progress_var.set("100%")
                    self._refresh_tree()
                    counts = Counter(f.category for f in self.findings)
                    self.status_var.set(
                        f"Scan complete: {len(self.findings)} exact targets. "
                        f"Surname {counts.get('Claimant Surname', 0)}, first name {counts.get('Claimant First Name', 0)}, "
                        f"SSN {counts.get('SSN', 0)}, DOB {counts.get('DOB', 0)}, address {counts.get('Claimant Address', 0)}."
                    )
                elif kind == "export_done":
                    _, output_path, audit_path, audit = msg
                    self._finish_operation()
                    self.progress["value"] = 100
                    self.progress_var.set("100%")
                    if audit["verification_passed"]:
                        self.status_var.set("Verified export complete.")
                        messagebox.showinfo(
                            "Scrubbing Complete",
                            f"Claimant PII removed and metadata sanitized.\n\nVerification: PASSED\nPDF: {output_path}\nAudit: {audit_path}",
                        )
                    else:
                        self.status_var.set("Export created; verification requires review.")
                        messagebox.showwarning(
                            "Review Required",
                            f"The PDF was created, but verification found a possible remaining target or metadata.\n\n"
                            f"Pages: {audit['pages_requiring_review']}\nCategories: {audit['failure_categories']}\nPDF: {output_path}\nAudit: {audit_path}",
                        )
                elif kind == "error":
                    self._finish_operation()
                    self.status_var.set(msg[1])
                    messagebox.showerror("PII Scrubber", msg[1])
        except queue.Empty:
            pass
        self.after(100, self._poll)


if __name__ == "__main__":
    PIIScrubberApp().mainloop()
