"""
app.py
------
Streamlit web application interface for the PII Redaction and Pseudonymization Pipeline.
"""

import streamlit as st
from redactor import redact_text

st.set_page_config(page_title="PII Redaction Pipeline", layout="centered")

st.title("🛡️ Automated PII Redaction & Evaluation System")
st.write("Detect, pseudonymize, or redact sensitive information (PII) from customer support logs and documents.")

# Sidebar controls
st.sidebar.header("Configuration")
fake_mode = st.sidebar.checkbox("Use Realistic Fake Data (Pseudonymization)", value=True, help="If unchecked, replaces PII with tags like [EMAIL], [PERSON]")

# Main text input area
st.subheader("Input Text / Ticket Log")
default_text = (
    "Ticket #101: Customer Sneha Iyer contacted support via sneha_iyer99@yahoo.co.in regarding billing. "
    "Registered callback at 080-25501234. Transaction processed using card 3782 822463 10005."
)
text_input = st.text_area("Paste text to analyze and redact:", default_text, height=150)

if st.button("Run Redaction Pipeline", type="primary"):
    if text_input.strip():
        # Perform redaction
        redacted_text, audit_trail = redact_text(text_input, fake_mode=fake_mode)

        # Display results side by side or sequentially
        st.subheader("🔒 Redacted Output")
        st.text_area("Processed Text", redacted_text, height=150)

        st.subheader("📋 Audit Trail & Detected Entities")
        if audit_trail:
            st.table(audit_trail)
        else:
            st.info("No PII entities detected in the provided text.")
    else:
        st.warning("Please enter some text to process.")