from enum import StrEnum, auto


_ABIS_FOLDER: str = "./shared/abis/"
_ALGO2_ABI_FILE: str = "Algo2ProxyReencryption.json"
_ALGO3_ABI_FILE: str = "Algo3SimpleEncryption.json"


class Algorithm(StrEnum):
    ALGO2 = auto()
    ALGO3 = auto()

    def get_contract_info_file_path(self) -> str:
        if self == Algorithm.ALGO2:
            return f"{_ABIS_FOLDER}{_ALGO2_ABI_FILE}"
        elif self == Algorithm.ALGO3:
            return f"{_ABIS_FOLDER}{_ALGO3_ABI_FILE}"
        else:
            raise RuntimeError("Unknown Algo selected")
