from __future__ import annotations

import calendar
import re
import subprocess

import app_v401  # applies the stable 4.0.1 metadata hardening
import app

APP_VERSION = "4.0.2"
OCR_TIMEOUT_SECONDS = 45

_original_run = subprocess.run
_original_ocr_words = app.PIIScrubberApp._ocr_words
_original_page_words = app.PIIScrubberApp._page_words
_original_discover_identity = app.PIIScrubberApp._discover_identity
_original_scan_targets = app.PIIScrubberApp._scan_targets
_original_verification_patterns = app.PIIScrubberApp._verification_patterns
_original_verify_output = app.PIIScrubberApp._verify_output

IDENTITY_LABEL_RE = re.compile(
    r"(?i)\b(?:DOB|DATE\s+OF\s+BIRTH|BIRTH\s+DATE|BORN|SSN|SOCIAL\s+SECURITY|"
    r"CLAIMANT\s+NAME|PATIENT\s+NAME|BENEFICIARY\s+NAME|APPLICANT\s+NAME|"
    r"HOME\s+ADDRESS|MAILING\s+ADDRESS|PHONE|TELEPHONE|E-?MAIL)\b"
)


def _capped_run(*args, **kwargs):
    timeout = kwargs.get("timeout")
    if timeout is None or timeout > OCR_TIMEOUT_SECONDS:
        kwargs["timeout"] = OCR_TIMEOUT_SECONDS
    return _original_run(*args, **kwargs)


# app.py calls subprocess.run directly. Cap that call without changing the stable base.
app.subprocess.run = _capped_run


def _name_parts(name: str) -> dict[str, object]:
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
    """Match the known claimant DOB in numeric and written-month forms."""
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
    try:
        words = _original_ocr_words(self, page)
    except subprocess.TimeoutExpired:
        words = []
        page_number = int(getattr(page, "number", -1)) + 1
        if page_number > 0:
            if not hasattr(self, "ocr_review_pages"):
                self.ocr_review_pages = set()
            self.ocr_review_pages.add(page_number)
    return words


def _page_words_v402(self, page, page_number: int, allow_ocr: bool = True):
    native = self._native_words(page)
    native_text = " ".join(w.text for w in native)
    # v4.0.1 skipped OCR whenever a page had >=20 native characters. That can
    # miss handwritten identity values on otherwise searchable forms. In 4.0.2,
    # identity-heavy forms receive an image OCR pass even when printed text exists.
    if allow_ocr and IDENTITY_LABEL_RE.search(native_text):
        ocr = self._ocr_words(page)
        if ocr:
            self.ocr_pages.add(page_number)
            return ocr
        # We cannot certify an identity-heavy page whose image OCR produced no
        # usable words. Preserve processing but require human review at export.
        if not hasattr(self, "ocr_review_pages"):
            self.ocr_review_pages = set()
        self.ocr_review_pages.add(page_number)
        return native
    return _original_page_words(self, page, page_number, allow_ocr)


def _word_pattern(value: str):
    value = str(value or "").strip(".")
    if not value:
        return None
    return re.compile(rf"(?i)(?<![A-Za-z]){re.escape(value)}\.?(?![A-Za-z])")


def _scan_targets_v402(self, doc, identity, cache):
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
            if len(middle) >= 2:
                pattern = _word_pattern(middle)
                if pattern:
                    self._add_matches(findings, words, page_number, pattern, "Claimant Middle Name", middle)
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
                    findings.append(app.Finding(
                        page_number, "Claimant Name / Middle Initial", match.group(0), rect,
                        "ocr" if any(w.source == "ocr" for w in words) else "native", 1.0,
                    ))
    return self._dedupe_findings(findings)


def _verification_patterns_v402(self):
    patterns = _original_verification_patterns(self)
    # The exact known DOB is identifying everywhere. Do not require a nearby DOB
    # label during verification; this closes the major 4.0.1 recall gap.
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


def _verify_output_v402(self, output_path: str) -> dict:
    result = _original_verify_output(self, output_path)
    review_pages = sorted(getattr(self, "ocr_review_pages", set()))
    if review_pages:
        result["verification_passed"] = False
        result["pages_requiring_review"] = sorted(
            set(result.get("pages_requiring_review", [])) | set(review_pages)
        )
        categories = set(result.get("failure_categories", []))
        categories.add("HANDWRITING / OCR REVIEW")
        result["failure_categories"] = sorted(categories)
    result["app_version"] = APP_VERSION
    result["ocr_review_pages"] = review_pages
    result["policy"] = (
        "claimant identity only; known DOB all-format recall; middle-name protection; "
        "identity-form image OCR; OCR timeout/review fail-closed"
    )
    return result


# Apply targeted 4.0.2 patches. v4.0.1 metadata sanitization remains in force.
app.APP_VERSION = APP_VERSION
app.PIIScrubberApp._discover_identity = _discover_identity_v402
app.PIIScrubberApp._dob_regex = staticmethod(_dob_regex_v402)
app.PIIScrubberApp._ocr_words = _ocr_words_v402
app.PIIScrubberApp._page_words = _page_words_v402
app.PIIScrubberApp._scan_targets = _scan_targets_v402
app.PIIScrubberApp._verification_patterns = _verification_patterns_v402
app.PIIScrubberApp._verify_output = _verify_output_v402


if __name__ == "__main__":
    app.PIIScrubberApp().mainloop()
