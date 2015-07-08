from src.pmpi import RawFormatError


def read_bytes(buffer, size):
    x = buffer.read(size)
    if len(x) != size:
        raise RawFormatError("raw input too short")
    return x
