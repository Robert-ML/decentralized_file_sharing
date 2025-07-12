from .isshiki_2013 import Isshiki, Isshiki_PublicParameters, Isshiki_PrivateKey, Isshiki_PublicKey


class PrencEncryptor:
    def __init__(self, public_params: Isshiki_PublicParameters, secret_key: Isshiki_PrivateKey | None = None) -> None:
        self._algo: Isshiki = Isshiki(public_params)

        self._secret_key: Isshiki_PrivateKey
        if secret_key is None:
            self._secret_key = self._algo.key_gen()
        else:
            self._secret_key = secret_key

    @property
    def public_key(self) -> Isshiki_PublicKey:
        return self._algo.gen_pub_key(self._secret_key)

    @property
    def secret_key(self) -> Isshiki_PrivateKey:
        return self._secret_key

    @property
    def public_parameters(self) -> Isshiki_PublicParameters:
        return self._algo.public_params

    @property
    def algo(self) -> Isshiki:
        return self._algo