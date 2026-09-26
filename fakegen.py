"""
fakegen.py
----------
Generates reproducible, realistic fake replacements for detected PII types
using the Faker library. 

To ensure consistency across documents (e.g., the same person's name or email 
always maps to the same fake substitute throughout a document run), we derive 
a deterministic per-value seed using hashlib.
"""

import hashlib
from faker import Faker

fake = Faker()
Faker.seed(42)  # Base seed


def _get_seeded_faker(pii_type: str, original_text: str):
    """Creates a local Faker instance seeded deterministically based on 
    the PII type and the normalized original text value."""
    hasher = hashlib.md5(f"{pii_type}:{original_text.strip().lower()}".encode("utf-8"))
    seed_int = int(hasher.hexdigest(), 16) % (2**32)
    local_fake = Faker()
    local_fake.seed_instance(seed_int)
    return local_fake


def generate_fake_replacement(pii_type: str, original_text: str) -> str:
    """Returns a realistic, deterministically generated fake substitute 
    matching the given PII type."""
    lf = _get_seeded_faker(pii_type, original_text)

    if pii_type == "EMAIL":
        return lf.email()
    elif pii_type == "PHONE":
        return lf.phone_number()
    elif pii_type == "PERSON":
        return lf.name()
    elif pii_type == "COMPANY":
        return f"{lf.company()} Ltd."
    elif pii_type == "SSN":
        return lf.ssn()
    elif pii_type == "IP_ADDRESS":
        return lf.ipv4()
    elif pii_type == "CREDIT_CARD":
        return lf.credit_card_number(card_type="visa")
    elif pii_type == "DATE_OF_BIRTH":
        return lf.date_of_birth(minimum_age=18, maximum_age=80).strftime("%B %d, %Y")
    elif pii_type == "ADDRESS":
        return f"Flat No. {lf.building_number()}, {lf.street_name()}, {lf.city()} 410501"
    else:
        return "[REDACTED]"