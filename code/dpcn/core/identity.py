from dataclasses import dataclass
from typing import Self

from core.common_identity import IDENTITY_KEY_T


@dataclass
class Identity:
    PICKLABLE_CONTAINER_T = dict[str, IDENTITY_KEY_T | str]

    id: IDENTITY_KEY_T

    public_key: str
    secret_key: str

    @property
    def key(self) -> IDENTITY_KEY_T:
        return self.id

    def __hash__(self) -> int:
        return hash(self.id)

    def get_picklable_dict(self) -> dict[str, IDENTITY_KEY_T | str]:
        return {
            "id": self.id,
            "public_key": self.public_key,
            "secret_key": self.secret_key,
        }

    @classmethod
    def from_unpicklabled_dict(cls, container: dict[str, IDENTITY_KEY_T | str]) -> Self:
        assert isinstance(container["id"], IDENTITY_KEY_T)
        assert isinstance(container["public_key"], str)
        assert isinstance(container["secret_key"], str)

        return cls(
            id=container["id"],
            public_key=container["public_key"],
            secret_key=container["secret_key"],
        )
