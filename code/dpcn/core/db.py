from __future__ import annotations
import os
import pickle
import logging

from pathlib import Path
from typing import Any

from core.common_identity import IDENTITY_KEY_T
from core.identity import Identity
from core.prenc_identity import PrencIdentity
from shared.python.utils.singleton import SingletonMeta


_DB_FILE: str = "db.pkl"
_DB_FOLDER: Path = Path("./storage/")
_DB_FILE_PATH: Path = _DB_FOLDER / _DB_FILE


class DB[Identity_T: (Identity, PrencIdentity)](metaclass=SingletonMeta):
    def __init__(self, stored: dict[IDENTITY_KEY_T, Identity_T] | None = None):
        self._storage: dict[IDENTITY_KEY_T, Identity_T] = stored or {}

    @classmethod
    def set_up(cls) -> None:
        stored_data: dict[IDENTITY_KEY_T, Identity_T] | None = cls.load()
        cls(stored_data)

    @staticmethod
    def load() -> dict[IDENTITY_KEY_T, Identity_T] | None:
        if os.path.exists(_DB_FILE_PATH) == False:
            logging.info(f"DB: Did not find the storage file: \"{_DB_FILE_PATH}\"")
            return None

        identities: dict[IDENTITY_KEY_T, Identity | PrencIdentity] = {}
        try:
            with open(_DB_FILE_PATH, mode="rb") as db_file:
                stored_data: list[dict[str, Any]] = pickle.load(db_file)

            for identity_container in stored_data:
                identity: Identity | PrencIdentity
                if "public_parameters" in identity_container:
                    identity = PrencIdentity.from_unpicklabled_dict(identity_container)
                else:
                    identity = Identity.from_unpicklabled_dict(identity_container)
                identities[identity.key] = identity

            logging.info(f"DB: Loaded file successfully")
        except Exception as e:
            logging.error(f"DB: Failed to load file: {repr(e)}", exc_info=e)

        return identities # type: ignore

    def save(self) -> None:
        _DB_FOLDER.mkdir(parents=True, exist_ok=True)

        try:
            with _DB_FILE_PATH.open(mode="wb") as db_file:
                identities: list[dict[str, Any]] = []
                for identity in self._storage.values():
                    identities.append(identity.get_picklable_dict())

                pickle.dump(identities, db_file, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception as e:
            logging.error(f"DB: Failed to save storage to file: \"{_DB_FILE_PATH.name}\"", exc_info=e)

    def add_identity(self, identity: Identity_T) -> Identity_T | None:
        """
        @returns if the identity was already present, the previous one
        """
        old_identity: Identity_T | None = self._storage.get(identity.key)
        self._storage[identity.key] = identity
        return old_identity

    def get_identity(self, key: IDENTITY_KEY_T) -> Identity_T | None:
        return self._storage.get(key)

    def get_db_byte_size(self) -> int:
        return _DB_FILE_PATH.stat().st_size
