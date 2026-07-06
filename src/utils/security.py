import re
import unicodedata
from typing import Tuple, List

# Cyrillic-to-Latin mapping for fallback normalization
CYRILLIC_TO_LATIN = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0455': 's', '\u0410': 'A', '\u0412': 'B', '\u0415': 'E',
    '\u041a': 'K', '\u041c': 'M', '\u041d': 'H', '\u041e': 'O',
    '\u0420': 'P', '\u0421': 'C', '\u0422': 'T', '\u0425': 'X',
}

def detect_mixed_scripts(text: str) -> Tuple[bool, List[str]]:
    """
    Programmatically detects if any word/label in the input text contains mixed alphabetic
    scripts (e.g., Latin mixed with Cyrillic or Greek characters), which is a key homograph attack vector.
    
    Returns (has_mixed_script, list_of_flagged_words).
    """
    if not text:
        return False, []
    
    # Split text into potential domain labels or words
    words = re.split(r'[\s/:\.@\(\)\[\]\-\u200b\u200c\u200d\ufeff]+', text)
    flagged_words = []
    has_mixed = False
    
    for word in words:
        if not word or len(word) < 2:
            continue
        
        scripts_found = set()
        for char in word:
            if not char.isalpha():
                continue
            try:
                name = unicodedata.name(char).upper()
                if "CYRILLIC" in name:
                    scripts_found.add("Cyrillic")
                elif "GREEK" in name:
                    scripts_found.add("Greek")
                elif "LATIN" in name:
                    scripts_found.add("Latin")
                # Other scripts can be added here if needed
            except ValueError:
                pass
        
        # If a single word mixes scripts (e.g. Cyrillic + Latin), flag it
        if len(scripts_found) > 1:
            has_mixed = True
            flagged_words.append(word)
            
    return has_mixed, flagged_words

def is_punycode_or_idn(text: str) -> Tuple[bool, bool, List[str]]:
    """
    Scans the text for internationalized domain names (IDN) or Punycode domains.
    Returns (has_idn, has_punycode, list_of_flagged_labels).
    """
    if not text:
        return False, False, []
        
    has_idn = False
    has_punycode = False
    flagged_labels = []
    
    # Simple regex to grab things that look like domain labels
    words = re.split(r'[\s/:\.@]+', text)
    for word in words:
        if not word:
            continue
        
        # Punycode prefix check
        if word.lower().startswith("xn--"):
            has_punycode = True
            flagged_labels.append(word)
            continue
            
        try:
            # Check if word contains non-ASCII characters
            word.encode('ascii')
        except UnicodeEncodeError:
            has_idn = True
            flagged_labels.append(word)
            
    return has_idn, has_punycode, flagged_labels

def normalize_obfuscations(text: str) -> Tuple[str, bool, bool]:
    """
    Strips zero-width characters and normalizes Cyrillic homoglyphs.
    Also programmatically checks for mixed script homoglyph bypasses.
    
    Returns (normalized_text, has_zero_width_chars, has_homoglyphs).
    """
    if not text:
        return text, False, False

    has_zw = False
    for char in ['\u200b', '\u200c', '\u200d', '\ufeff']:
        if char in text:
            has_zw = True
            text = text.replace(char, '')

    has_homoglyphs = False
    
    # First check programmatically for script mixing
    mixed_found, _ = detect_mixed_scripts(text)
    idn_found, _, _ = is_punycode_or_idn(text)
    if mixed_found or idn_found:
        has_homoglyphs = True

    # Run character-by-character translation map normalization
    normalized = []
    for ch in text:
        if ch in CYRILLIC_TO_LATIN:
            has_homoglyphs = True
            normalized.append(CYRILLIC_TO_LATIN[ch])
        else:
            normalized.append(ch)

    return "".join(normalized), has_zw, has_homoglyphs

def refang_indicator(text: str) -> str:
    """Convert defanged IOC notation back to standard internet formats."""
    if not text:
        return text
    text = re.sub(r'\[:\]|\(:\)', ':', text)
    text = re.sub(r'\[\.\]|\(\.\)|\[dot\]|\(dot\)', '.', text, flags=re.IGNORECASE)
    text = re.sub(r'hxxps?://', lambda m: m.group(0).replace('x', 't'), text, flags=re.IGNORECASE)
    text = re.sub(r'\bhxxps?\b', lambda m: m.group(0).replace('x', 't'), text, flags=re.IGNORECASE)
    text = re.sub(r'\[at\]|\(at\)', '@', text, flags=re.IGNORECASE)
    return text
