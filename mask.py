import re
import sys

def mask_sensitive(text: str) -> str:
    # Masque la valeur du cookie de session
    text = re.sub(r'session=[^;\s\n]+', 'session=***MASKED***', text)
    # Masque le csrf_token dans un corps de formulaire (POST)
    text = re.sub(r'csrf_token=[^&\s\n]+', 'csrf_token=***MASKED***', text)
    # Masque le csrf_token dans un champ HTML value="..."
    text = re.sub(r'(name="csrf_token"\s+value=")[^"]+(")', r'\1***MASKED***\2', text)
    return text

if __name__ == "__main__":
    raw = sys.stdin.read()
    print(mask_sensitive(raw))