from .isshiki_2013 import Isshiki, Isshiki_PublicParameters, Isshiki_PrivateKey, Isshiki_PublicKey, Isshiki_ReEncKey

def get_re_encryption_key(public_params: Isshiki_PublicParameters, owner_sk: Isshiki_PrivateKey, client_pk: Isshiki_PublicKey) -> Isshiki_ReEncKey:
    algo: Isshiki = Isshiki(public_params)

    return algo.re_key(
        ski=owner_sk,
        pkj=client_pk,
    )
