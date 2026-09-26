# PII Redaction Pipeline: Evaluation Strategy & Metrics

## 1. Evaluation Approach
Our evaluation framework (`evaluate.py`) compares model-predicted PII spans against a gold-standard hand-labeled dataset (`ground_truth.json`) line by line. 

A match is recorded as a **True Positive (TP)** if:
- The detected PII type matches the ground truth type.
- The detected text span overlaps or matches the expected ground truth token string.

## 2. Core Metrics Tracked
- **Precision ($\frac{TP}{TP + FP}$)**: Measures how many of the flagged PII items were actual sensitive entities (minimizing False Positives).
- **Recall ($\frac{TP}{TP + FN}$)**: Measures how many actual PII entities present in the text were successfully detected (minimizing False Negatives).
- **F1-Score ($2 \times \frac{Precision \times Recall}{Precision + Recall}$)**: The harmonic mean balancing precision and recall.
- **Accuracy**: Overall correctness across all prediction classifications.

## 3. Results Summary
- **Overall Precision**: 0.833
- **Overall Recall**: 0.909
- **Overall F1-Score**: 0.870
- **Overall Accuracy**: 0.769

## 4. Key Architectural Decisions
- **Hybrid Detection**: Combined deterministic Regular Expressions (for Emails, Phone numbers, SSNs, Credit Cards with Luhn checksum validation, IP addresses, and Dates of Birth) with spaCy's NER model (`en_core_web_sm`) for unstructured entities (Person names and Companies).
- **False Positive Reduction**: Implemented extensive stopword lists and context boundary checks to filter out generic corporate terms and place names from being misclassified as companies or persons.