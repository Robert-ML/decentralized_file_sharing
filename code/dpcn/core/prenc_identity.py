from typing import Self
from dataclasses import dataclass

from shared.python.crypto.prenc.isshiki_2013 import (
    Isshiki_PrivateKey,
    Isshiki_PublicKey,
    Isshiki_PublicParameters,
)

from core.common_identity import IDENTITY_KEY_T


@dataclass
class PrencIdentity:
    PICKLABLE_CONTAINER_T = dict[str, IDENTITY_KEY_T | str | dict[str, int]]

    id: IDENTITY_KEY_T
    user: str

    public_key: Isshiki_PublicKey
    secret_key: Isshiki_PrivateKey

    public_parameters: Isshiki_PublicParameters

    @property
    def key(self) -> IDENTITY_KEY_T:
        return self.id

    def __hash__(self) -> int:
        return hash(self.id)

    def get_picklable_dict(self) -> PICKLABLE_CONTAINER_T:
        return {
            "id": self.id,
            "user": self.user,
            "public_key": self.public_key.to_dict(), # even if it can be generated later, storage is cheap
            "secret_key": self.secret_key.to_dict(),
            "public_parameters": self.public_parameters.to_dict(),
        }

    @classmethod
    def from_unpicklabled_dict(cls, container: PICKLABLE_CONTAINER_T) -> Self:
        assert isinstance(container["id"], IDENTITY_KEY_T)
        assert isinstance(container["user"], str)
        assert isinstance(container["public_key"], dict)
        assert isinstance(container["secret_key"], dict)
        assert isinstance(container["public_parameters"], dict)

        return cls(
            id=container["id"],
            user=container["user"],
            public_key=Isshiki_PublicKey.from_dict(container["public_key"]),
            secret_key=Isshiki_PrivateKey.from_dict(container["secret_key"]),
            public_parameters=Isshiki_PublicParameters.from_dict(container["public_parameters"]),
        )
