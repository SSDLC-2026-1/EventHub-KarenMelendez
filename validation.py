"""
payment_validation.py

Skeleton file for input validation exercise.
You must implement each validation function according to the
specification provided in the docstrings.

All validation functions must return:

    (clean_value, error_message)

Where:
    clean_value: normalized/validated value (or empty string if invalid)
    error_message: empty string if valid, otherwise error description
"""

import re
import unicodedata
from datetime import datetime
from typing import Tuple, Dict


# =============================
# Regular Patterns
# =============================


CARD_DIGITS_RE = re.compile(r"")     # digits only
CVV_RE = re.compile(r"")             # 3 or 4 digits
EXP_RE = re.compile(r"")             # MM/YY format
EMAIL_BASIC_RE = re.compile(r"")     # basic email structure
NAME_ALLOWED_RE = re.compile(r"")    # allowed name characters


# =============================
# Utility Functions
# =============================

def normalize_basic(value: str) -> str:
    """
    Normalize input using NFKC and strip whitespace.
    """
    return unicodedata.normalize("NFKC", (value or "")).strip()

def luhn_is_valid(number: str) -> bool:
    if not number.isdigit():
        return False

    total = 0
    reverse_digits = number[::-1]

    for i in range(len(reverse_digits)):
        digit = int(reverse_digits[i])

        # Duplicar cada segundo dígito
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9

        total += digit

    return total % 10 == 0


# =============================
# Field Validations
# =============================

def validate_card_number(card_number: str) -> Tuple[str, str]:
    

    card_number = card_number.strip().replace(" ", "").replace("-", "")
    error_message = " "
    if not 19 >= len(card_number) >= 13:
        error_message = "Length between 13 and 19 digits"
    elif not card_number.isdigit():
        error_message = "Card number must be digits"
    elif not luhn_is_valid(card_number):   
        error_message = "Invalid card number"
    else:
        return card_number, error_message
    
    return "",error_message


def validate_exp_date(exp_date: str) -> Tuple[str, str]:

    exp_date = exp_date.strip()

    # Debe ser exactamente 4 números
    if not exp_date.isdigit() or len(exp_date) != 4:
        return "", "Invalid Card ID"

    month = int(exp_date[:2])
    year = 2000 + int(exp_date[2:])  # 28 -> 2028

    if month < 1 or month > 12:
        return "", "Invalid Card ID"

    now = datetime.now()
    
    if year < now.year or (year == now.year and month < now.month):
        return "", "Expired Card"

    return exp_date, ""


def validate_cvv(cvv: str) -> Tuple[str, str]:
    
    error_message = " "
    cvv = cvv.strip()
    if 4 >=  len(cvv) >= 3 and cvv.isdigit():
        return cvv,error_message
    else:
        error_message = "Invalid CVV"

    return " ", error_message


def validate_billing_email(billing_email: str) -> Tuple[str, str]:

    normalized_email=billing_email.strip().lower()
    
    if len(billing_email) > 254:
        return "", "Max length 254"
    
    if normalized_email.count("@") != 1:
       return "", "Invalid email format"

    local_part, domain = normalized_email.split("@")

    if not local_part or not domain:
       return "", "Invalid email format"

    if "." not in domain:
       return "", "Invalid email format"

    if domain.startswith(".") or domain.endswith("."):
       return "", "Invalid email format"

    if " " in normalized_email:
       return "", "Invalid email format"

    return normalized_email, ""



def validate_name_on_card(name_on_card: str) -> Tuple[str, str]:
    if not isinstance(name_on_card, str):
        return "", "Name must be a string"

    normalized = name_on_card.strip()
    normalized = " ".join(normalized.split())

 
    if len(normalized) < 2 or len(normalized) > 60:
        return "", "Name must be between 2 and 60 characters"

    for char in normalized:
        if not (
            char.isalpha()
            or char == " "
            or char == "-"
            or char == "'"
        ):
            return "", "Name contains invalid characters"

    return normalized, ""

# =============================
# Orchestrator Function
# =============================

def validate_payment_form(
    card_number: str,
    exp_date: str,
    cvv: str,
    name_on_card: str,
    billing_email: str
) -> Tuple[Dict, Dict]:
    """
    Orchestrates all field validations.

    Returns:
        clean (dict)  -> sanitized values safe for storage/use
        errors (dict) -> field_name -> error_message
    """

    clean = {}
    errors = {}

    card, err = validate_card_number(card_number)
    if err:
        errors["card_number"] = err
    clean["card"] = card

    exp_clean, err = validate_exp_date(exp_date)
    if err:
        errors["exp_date"] = err
    clean["exp_date"] = exp_clean

    _, err = validate_cvv(cvv)
    if err:
        errors["cvv"] = err

    name_clean, err = validate_name_on_card(name_on_card)
    if err:
        errors["name_on_card"] = err
    clean["name_on_card"] = name_clean

    email_clean, err = validate_billing_email(billing_email)
    if err:
        errors["billing_email"] = err
    clean["billing_email"] = email_clean

    return clean, errors
