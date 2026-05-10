import logging
import pwnedpasswords

logger = logging.getLogger(__name__)

def is_pwned(plaintext: str) -> int: 
    try: 
        return pwnedpasswords.check(plaintext)
    except Exception as e: 
        logger.warning("HIBP check failed for password: %s", e)
        return -1 
    
