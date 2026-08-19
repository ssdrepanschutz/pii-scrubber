from __future__ import annotations

import inspect

import fitz

import app


APP_VERSION = "4.0.1"

# These are the user/document metadata fields that may carry identifying data.
# PyMuPDF also reports structural properties such as PDF format and encryption;
# those are not embedded personal metadata and must not cause a false failure.
SENSITIVE_METADATA_KEYS = (
    "title",
    "author",
    "subject",
    "keywords",
    "creator",
    "producer",
    "creationDate",
    "modDate",
    "trapped",
)


_original_sanitize_document = app.PIIScrubberApp._sanitize_document
_original_verify_output = app.PIIScrubberApp._verify_output


def _blank_sensitive_metadata(doc: fitz.Document) -> None:
    blank = {key: "" for key in SENSITIVE_METADATA_KEYS}
    try:
        doc.set_metadata(blank)
    except Exception:
        # Fall back to the broad clear supported by older PyMuPDF builds.
        try:
            doc.set_metadata({})
        except Exception:
            pass

    try:
        doc.del_xml_metadata()
    except Exception:
        pass


def _sanitize_document_v401(doc: fitz.Document) -> None:
    # Run the V4 sanitization first: attachments, embedded files, JavaScript,
    # thumbnails, standard metadata, and XMP are removed where supported.
    _original_sanitize_document(doc)

    # Then explicitly clear the identifying metadata fields again so a library
    # operation cannot re-populate Creator / Producer / dates after scrub().
    _blank_sensitive_metadata(doc)


def _metadata_status(output_path: str) -> tuple[bool, list[str], bool]:
    residual_fields: list[str] = []
    xmp_present = False

    with fitz.open(output_path) as doc:
        metadata = doc.metadata or {}
        for key in SENSITIVE_METADATA_KEYS:
            value = metadata.get(key)
            if str(value or "").strip():
                residual_fields.append(key)

        try:
            xmp = doc.get_xml_metadata()
            xmp_present = bool(str(xmp or "").strip())
        except Exception:
            xmp_present = False

    clean = not residual_fields and not xmp_present
    return clean, sorted(residual_fields), xmp_present


def _verify_output_v401(self: app.PIIScrubberApp, output_path: str) -> dict:
    # Keep V4's claimant-PII verification logic, then correct the metadata test.
    result = _original_verify_output(self, output_path)

    metadata_clean, residual_fields, xmp_present = _metadata_status(output_path)

    # The original verifier already populated page and category failures for
    # remaining claimant PII. Recalculate the overall PASS from those results
    # plus the corrected metadata verification.
    pii_failures = bool(result.get("pages_requiring_review") or result.get("failure_categories"))

    result["app_version"] = APP_VERSION
    result["metadata_clean"] = metadata_clean
    result["metadata_residual_fields"] = residual_fields
    result["xmp_metadata_present"] = xmp_present
    result["verification_passed"] = (not pii_failures) and metadata_clean
    return result


# Patch the V4 class before the application window is created.
app.APP_VERSION = APP_VERSION
app.PIIScrubberApp._sanitize_document = staticmethod(_sanitize_document_v401)
app.PIIScrubberApp._verify_output = _verify_output_v401


if __name__ == "__main__":
    app.PIIScrubberApp().mainloop()
