from __future__ import annotations

import json

from dataclasses import dataclass
import matplotlib.pyplot as plt
from pathlib import Path
from pprint import pformat
from typing import Any, Self

from shared.python.utils.metrics import MetricType


DATA_DPCN_FOLDER: Path = Path("./data/dpcn/")


def assert_field[T](dict: dict[str, Any], field: str, type: type[T]) -> T:
    assert isinstance(dict[field], type), f"Field of not the expected type {type}"
    return dict[field]


@dataclass
class StorageUsedData:
    file_no: int
    bytes_used: int

    def key(self) -> int:
        return self.file_no

    @classmethod
    def get_storage_used_data(cls, file: Path) -> dict[int, Self]:
        data_raw: list[dict[str, str | int]]
        with file.open("r") as f:
            data_raw = json.load(f)

        ret: dict[int, Self] = {}
        for data_point in data_raw:
            file_no: int = assert_field(data_point, "file_no", int)
            storage_used: int = assert_field(data_point, "bytes_used", int)

            ret[file_no] = cls(
                file_no,
                storage_used,
            )

        return ret


@dataclass
class PreparedData:
    data: list[StorageUsedData]

    @property
    def indexes(self) -> list[int]:
        return list(range(1, len(self.data) + 1))

    @property
    def values(self) -> list[int]:
        first: int = self.data[0].bytes_used
        second: int = self.data[1].bytes_used

        # we want to adjust the data to start from approximately 0
        delta = first - (second - first)

        return [entry.bytes_used - delta for entry in self.data]


def load_data() -> dict[int, StorageUsedData]:
    dpcn_storage_used_data: Path = DATA_DPCN_FOLDER / MetricType.A2_DPCN_STORAGE_USED.get_file_name()

    dpcn_data: dict[int, StorageUsedData] = StorageUsedData.get_storage_used_data(dpcn_storage_used_data)

    return dpcn_data


def prepare_data(loaded_data: dict[int, StorageUsedData]) -> PreparedData:
    prepared_data: list[StorageUsedData] = []

    sorted_file_no: list[int] = list(sorted(loaded_data.keys()))

    file_no: int
    for file_no in sorted_file_no:
        prepared_data.append(loaded_data[file_no])

    return PreparedData(prepared_data)


def plot_data(data: PreparedData) -> None:
    # Plotting
    plt.figure(figsize=(10, 5))
    plt.plot(data.indexes, data.values, marker='o', linestyle='-', color='blue')

    # Add labels and title
    plt.xlabel('File Credentials Generated')
    plt.ylabel('Bytes Used')
    # plt.title('Storage Used vs File Credentials Generated (Showing Linear Dependency)')
    plt.grid(True)

    plt.tight_layout()
    plt.show()



def main():
    loaded_data: dict[int, StorageUsedData] = load_data()
    prepared_data: PreparedData = prepare_data(loaded_data)
    plot_data(prepared_data)

if __name__ == "__main__":
    main()
