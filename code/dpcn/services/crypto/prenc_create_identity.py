import secrets

from shared.python.crypto.prenc.isshiki_2013 import (
    Isshiki,
    Isshiki_PublicKey,
    Isshiki_PrivateKey,
    Isshiki_PublicParameters,
)

from core.prenc_identity import PrencIdentity


def create_prenc_identity(user: str) -> PrencIdentity:
    """
    Create a new identity for re-encryption
    """
    id: int = int.from_bytes(secrets.token_bytes(256 // 8), 'big', signed=False)

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
