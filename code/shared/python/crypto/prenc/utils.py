import math
import secrets


def get_secure_pseudo_rand_in_range(range: int) -> int:

    res: int = None
    tries: int = 100
    try_no: int = 0

    while try_no < tries:

        bits_req: int = int(math.ceil(math.log2(range)))
        bytes_req: int = int(math.ceil(bits_req / 8))

        rand: bytes = secrets.token_bytes(bytes_req)
        rand: int = int.from_bytes(rand, byteorder="big", signed=False)

        # if not in the range, try again, this should make the random function
        # uniform supposing the underlying random function is itself uniform
        if rand < range:
            res = rand
            break

        try_no += 1

    if(res == None):
        print("---???!!!---", end = "\n\n")

    return res

