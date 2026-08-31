from __future__ import annotations

import calendar
import re
import subprocess

import app_v401  # applies the 4.0.1 metadata hardening patches
import app

APP_VERSION = "4.0.2"
OCR_TIMEOUT_SECONDS = 45

_original_ocr_words = app.PIIScrubberApp._ocr_words
_original_discover_identity = app.PIIScrubberApp._discover_identity
_original_scan_targets = app.PIIScrubberApp._scan_targets
_original_verification_patterns = app.PIIScrubberApp._verification_patterns


def _name_parts(name: str) -> dict[str, object]:
    """Return claimant first/middle/surname parts without changing provider policy."""
    text = " ".join(str(name or "").strip().split())
    if not text:
        return {}
    if "," in text:
        left, right = text.split(",", 1)
        surname_tokens = re.findall(r"[A-Za-z][A-Za-z'\-.]*", left)
        given = re.findall(r"[A-Za-z][A-Za-z'\-.]*", right)
        surname = surname_tokens[-1].strip(".") if surname_tokens else ""
    else:
        given = re.findall(r"[A-Za-z][A-Za-z'\-.]*", text)
        surname = given[-1].strip(".") if len(given) >= 2 else ""
        given = given[:-1] if surname else given
    first = given[0].strip(".") if given else ""
    middles = [x.strip(".") for x in given[1:] if x.strip(".")]
    return {"first": first, "middle": middles, "surname": surname}


def _discover_identity_v402(self, doc):
    identity, cache = _original_discover_identity(self, doc)
    parts = _name_parts(str(identity.get("name") or ""))
    middles = list(parts.get("middle") or [])
    if middles:
        identity["middle"] = middles
        identity["middle_initials"] = [m[0] for m in middles if m]
    return identity, cache


def _dob_regex_v402(dob):
    """Known claimant DOB in numeric and written-month forms; no DOB-label dependency."""
    year, month, day = dob
    yy = str(year)[-2:]
    full = calendar.month_name[month]
    abbr = calendar.month_abbr[month]
    month_word = rf"(?:{re.escape(full)}|{re.escape(abbr)}\.?)"
    return re.compile(
        rf"(?<!\d)(?:"
        rf"0?{month}\s*[/.\-]\s*0?{day}\s*[/.\-]\s*(?:{year}|{yy})|"
        rf"{year}\s*[/.\-]\s*0?{month}\s*[/.\-]\s*0?{day}|"
        rf"{month_word}\s+0?{day}(?:st|nd|rd|th)?\s*,?\s+{year}|"
        rf"0?{day}(?:st|nd|rd|th)?\s+{month_word}\s*,?\s+{year}"
        rf")(?!\d)",
        re.I,
    )


def _ocr_words_v402(self, page):
    """Keep OCR local but fail fast instead of appearing frozen on a bad page."""
    try:
        return _original_ocr_words(self, page)
    except subprocess.TimeoutExpired:
        # A timeout is review-worthy; do not certify that page through OCR.
        page_number = int(getattr(page, "number", -1)) + 1
        if page_number > 0:
            if not hasattr(self, "ocr_review_pages"):
                self.ocr_review_pages = set()
            self.ocr_review_pages.add(page_number)
        return []


def _word_pattern(value: str):
    value = str(value or "").strip(".")
    if not value:
        return None
    return re.compile(rf"(?i)(?<![A-Za-z]){re.escape(value)}\.?(?![A-Za-z])")


def _scan_targets_v402(self, doc, identity, cache):
    # Base scan handles first/surname/SSN/address and now uses the broader DOB regex.
    findings = _original_scan_targets(self, doc, identity, cache)
    middles = list(identity.get("middle") or [])
    initials = list(identity.get("middle_initials") or [])
    if not middles and not initials:
        return findings

    for idx in range(doc.page_count):
        page_number = idx + 1
        words = cache.get(idx)
        if words is None:
            words = self._page_words(doc.load_page(idx), page_number, allow_ocr=True)
        for middle in middles:
            # Full middle names are claimant identifiers once learned from the claimant full name.
            if len(middle) >= 2:
                pattern = _word_pattern(middle)
                if pattern:
                    self._add_matches(findings, words, page_number, pattern, "Claimant Middle Name", middle)
        # Middle initials are only scrubbed when they occur in a claimant-name context,
        # avoiding destruction of unrelated single-letter clinical content.
        joined, spans = self._joined(words)
        first = str(identity.get("first") or "")
        surname = str(identity.get("surname") or "")
        for initial in initials:
            if not initial or not first or not surname:
                continue
            pattern = re.compile(
                rf"(?i)(?<![A-Za-z]){re.escape(first)}\s+{re.escape(initial)}\.?\s+{re.escape(surname)}(?![A-Za-z])"
            )
            for match in pattern.finditer(joined):
                rect = self._match_rect(words, spans, match.start(), match.end())
                if rect:
                    findings.append(app.Finding(page_number, "Claimant Name / Middle Initial", match.group(0), rect, "ocr" if any(w.source == "ocr" for w in words) else "native", 1.0))
    return self._dedupe_findings(findings)


def _verification_patterns_v402(self):
    patterns = _original_verification_patterns(self)
    # Replace the old context-limited DOB verifier with the exact known-DOB matcher.
    patterns = [p for p in patterns if p[0] != "DOB"]
    dob = self.identity.get("dob")
    if dob:
        patterns.append(("DOB", _dob_regex_v402(dob), None))
    for middle in list(self.identity.get("middle") or []):
        if len(middle) >= 2:
            pattern = _word_pattern(middle)
            if pattern:
                patterns.append(("Claimant Middle Name", pattern, None))
    return patterns


# Apply the targeted 4.0.2 patches. 4.0.1 metadata verification remains in force.
app.APP_VERSION = APP_VERSION
app.PIIScrubberApp._discover_identity = _discover_identity_v402
app.PIIScrubberApp._dob_regex = staticmethod(_dob_regex_v402)
app.PIIScrubberApp._ocr_words = _ocr_words_v402
app.PIIScrubberApp._scan_targets = _scan_targets_v402
app.PIIScrubberApp._verification_patterns = _verification_patterns_v402

# The base OCR function currently has its own 180-second subprocess timeout. The wrapper
# prevents an uncaught timeout from killing the scan. A follow-up refactor should move
# OCR_TIMEOUT_SECONDS into app.py so the subprocess itself uses the shorter limit.

if __name__ == "__main__":
    app.PIIScrubberApp().mainloop()
