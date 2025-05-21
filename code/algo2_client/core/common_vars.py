import asyncio

from concurrent.futures import ProcessPoolExecutor

from shared.python.utils.singleton import SingletonMeta


_CPU_CORES_TO_USE: int = 12


class CommonVars(metaclass=SingletonMeta):
    def __init__(self, ) -> None:
        self.contract_transaction_lock: asyncio.Lock = asyncio.Lock()
        self.running: bool = True

        self.executor: ProcessPoolExecutor = ProcessPoolExecutor(max_workers=_CPU_CORES_TO_USE)

    @classmethod
    def set_up(cls) -> None:
        cls()
