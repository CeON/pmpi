from hashlib import sha256
from ecdsa.keys import SigningKey
from pmpi.exceptions import RawFormatError
from pmpi.public_key import PublicKey


def read_bytes(buffer, size):
    x = buffer.read(size)
    if len(x) != size:
        raise RawFormatError("raw input too short")
    return x


def read_uint32(buffer):
    return int.from_bytes(read_bytes(buffer, 4), 'big')


def read_sized_bytes(buffer):
    return read_bytes(buffer, read_uint32(buffer))


def read_string(buffer):
    return read_sized_bytes(buffer).decode('utf-8')


def double_sha(b):
    return sha256(sha256(b).digest()).digest()


def sign_object(public_key, private_key, obj):
    """
    :type public_key: PublicKey
    :type private_key: SigningKey
    :type obj: AbstractSignedObject
    """
    obj.sign(public_key, private_key.sign_deterministic(obj.unsigned_raw()))


