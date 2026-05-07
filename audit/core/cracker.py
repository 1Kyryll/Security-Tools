from core.hashers import hash_password

RULES = [
    lambda w: w, 
    lambda w: w.capitalize(), 
    lambda w: w.upper(),
    lambda w: w + "1", 
    lambda w: w + "123", 
    lambda w: w + "!",
    lambda w: w.replace("a", "@").replace("o", "0").replace("e", "3"), 
]

def candidates(word: str): 
    for rule in RULES: 
        yield rule(word)

def crack(
        target_hashes: set[str], 
        algo: str, 
        wordlist_path: str, 
        on_progress=None
) -> dict[str, str]: 
    cracked = {}
    remaining = set(target_hashes)
    tried = 0 

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f: 
        for line in f: 
            word = line.strip()
            if not word:
                continue

            for candidate in candidates(word): 
                candidate_hash = hash_password(candidate, algo)
                tried += 1 

                if candidate_hash in remaining:
                    cracked[candidate_hash] = candidate 
                    remaining.discard(candidate_hash)

                    if not remaining: 
                        return cracked
                
            if on_progress and tried % 1000 == 0:
                on_progress(tried, len(cracked), len(target_hashes))

    return cracked