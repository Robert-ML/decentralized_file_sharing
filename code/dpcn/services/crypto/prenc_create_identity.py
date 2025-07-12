import secrets

from shared.python.crypto.prenc.isshiki_2013 import (
    Isshiki,
    Isshiki_PublicKey,
    Isshiki_PrivateKey,
    Isshiki_PublicParameters,
)
from shared.python.crypto.utils import get_random_int

from core.prenc_identity import PrencIdentity


def create_prenc_identity(user: str) -> PrencIdentity:
    """
    Create a new identity for re-encryption
    """
    id: int = get_random_int()

    algo: Isshiki = Isshiki()
    prenc_secret_key: Isshiki_PrivateKey = algo.key_gen()
    prenc_public_key: Isshiki_PublicKey = algo.gen_pub_key(prenc_secret_key)

    return PrencIdentity(
        id=id,
        user=user,
        public_key=prenc_public_key,
        secret_key=prenc_secret_key,
        public_parameters=algo.public_params
    )
