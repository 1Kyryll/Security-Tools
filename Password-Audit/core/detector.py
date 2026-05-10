import re

# (length_in_hex_chars, algorithm_name) - checked in order
HASH_PATTERNS = [
    (32, "md5_or_ntlm"),
    (40, "sha1"), 
    (64, "sha256"),
    (128, "sha512"), 
]

def detect(hash_str: str) -> str: 
    h = hash_str.strip().lower()

    if h.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt"
    if h.startswith("$argon2"):
        return "argon2"
    if h.startswith("$6$"):
        return "sha512crypt"
    
    if re.fullmatch(r"[a-f0-9]+", h): 
        for length, algo in HASH_PATTERNS:
            if len(h) == length: 
                return algo 
    
    return "unknown"