from typing import Self

from shared.python.crypto.prenc.encryptor import PrencEncryptor
from shared.python.crypto.prenc.isshiki_2013 import Isshiki_PrivateKey, Isshiki_PublicParameters


class FilePrencCredentials:
    def __init__(self, file_id: int, encryptor: PrencEncryptor) -> None:
        self._file_id: int = file_id
        self._encryptor: PrencEncryptor = encryptor

    @classmethod
    def from_list_of_parameters(cls, parameters: list[int]) -> Self:
        # there are 19 parameters expected
        assert len(parameters) == 19

        file_id: int = parameters[0]
        public_params: Isshiki_PublicParameters = Isshiki_PublicParameters.from_list(
            parameters=parameters[1:17]
        )
        private_key: Isshiki_PrivateKey = Isshiki_PrivateKey(
            sk1=parameters[17],
            sk2=parameters[18],
        )

        encryptor: PrencEncryptor = PrencEncryptor(
            public_params=public_params,
            secret_key=private_key
        )

        return cls(
            file_id=file_id,
            encryptor=encryptor,
        )

    @property
    def file_id(self) -> int:
        return self._file_id

    @property
    def encryptor(self) -> PrencEncryptor:
        return self._encryptor
