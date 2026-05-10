import hashlib

SLOW_ALGOS = {
    "bcrypt", 
    "argon2",
    "scrypt", 
    "pbkdf2"
}

def hash_password(plaintext: str, algo: str) -> str: 
    pwd_bytes = plaintext.encode("utf-8")

    if algo == "md5": 
        return hashlib.md5(pwd_bytes).hexdigest()
    if algo == "sha1": 
        return hashlib.sha1(pwd_bytes).hexdigest()
    if algo == "sha256": 
        return hashlib.sha256(pwd_bytes).hexdigest()
    if algo == "sha512":
        return hashlib.sha512(pwd_bytes).hexdigest()
    
    if algo == "ntlm": 
        return hashlib.new("md4", plaintext.encode("utd-16-le")).hexdigest()
    
    raise ValueError(f"Unsupported algorithm: {algo}")