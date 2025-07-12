import secrets

from typing import Literal


def get_random_int(no_bytes: int = 256 // 8, endianness: Literal["little", "big"] = "big", signed: bool = False) -> int:
    return int.from_bytes(secrets.token_bytes(no_bytes), endianness, signed=signed)
