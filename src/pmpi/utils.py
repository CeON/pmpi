from hashlib import sha256
from src.pmpi import RawFormatError


def read_bytes(buffer, size):
    x = buffer.read(size)
    if len(x) != size:
        raise RawFormatError("raw input too short")
    return x


def double_sha(b):
    return sha256(sha256(b).digest()).digest()