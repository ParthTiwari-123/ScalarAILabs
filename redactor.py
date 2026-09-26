"""
redactor.py
-----------
Public APIs to perform clean text substitution and file-level redaction
(supporting plain text and Word .docx documents) while maintaining 
an audit trail of changes.
"""

import os
from typing import List, Dict, Tuple
from detectors import detect_all, Span
from fakegen import generate_fake_replacement

try:
    from docx import Document
except ImportError:
    Document = None


def redact_text(text: str, fake_mode: bool = True) -> Tuple[str, List[Dict[str, str]]]:
    """Detects all PII spans in a text string and replaces them either 
    with fake data or a generic [REDACTED] tag. Returns the modified text 
    and an audit log of replacements."""
    spans = detect_all(text)
    # Sort spans in reverse order so string indices don't shift during replacement
    spans_sorted = sorted(spans, key=lambda s: s.start, reverse=True)
    
    modified_text = text
    audit_trail = []

    for span in spans_sorted:
        replacement = generate_fake_replacement(span.pii_type, span.text) if fake_mode else f"[{span.pii_type}]"
        modified_text = modified_text[:span.start] + replacement + modified_text[span.end:]
        audit_trail.append({
            "type": span.pii_type,
            "original": span.text,
            "replacement": replacement,
            "start": span.start,
            "end": span.end
        })

    audit_trail.reverse()
    return modified_text, audit_trail


def redact_plain_file(input_path: str, output_path: str, fake_mode: bool = True):
    """Reads a plain text file, redacts PII line by line, and writes out the result."""
    with open(input_path, "r", encoding="utf-8") as f:
        content = f.read()

    redacted_content, _ = redact_text(content, fake_mode=fake_mode)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(redacted_content)


def redact_docx(input_path: str, output_path: str, fake_mode: bool = True):
    """Redacts PII inside Word (.docx) documents, preserving paragraph layout, 
    tables, headers, and footers."""
    if Document is None:
        raise ImportError("python-docx is required to process .docx files. Run 'pip install python-docx'.")

    doc = Document(input_path)

    # Process paragraphs
    for p in doc.paragraphs:
        if p.text.strip():
            new_text, _ = redact_text(p.text, fake_mode=fake_mode)
            if new_text != p.text:
                # Clear existing runs and set new text while maintaining basic structure
                p.text = new_text

    # Process tables
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                if cell.text.strip():
                    new_text, _ = redact_text(cell.text, fake_mode=fake_mode)
                    if new_text != cell.text:
                        cell.text = new_text

    doc.save(output_path)