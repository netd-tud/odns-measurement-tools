import hashlib

def hash_string(input_string: str, algorithm="sha256") -> str:
    """Hashes a string using the specified algorithm and returns the hex digest."""
    hasher = hashlib.new(algorithm)
    hasher.update(input_string.encode('utf-8'))
    return hasher.hexdigest()