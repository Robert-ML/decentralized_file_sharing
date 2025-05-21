import asyncio

from shared.python.utils.singleton import SingletonMeta


class CommonVars(metaclass=SingletonMeta):
    def __init__(self) -> None:
        self.contract_transaction_lock: asyncio.Lock = asyncio.Lock()
        self.running: bool = True

    @classmethod
    def set_up(cls) -> None:
        cls()
