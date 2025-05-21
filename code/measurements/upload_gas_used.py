from __future__ import annotations

import json

from dataclasses import dataclass
import matplotlib.pyplot as plt
from pathlib import Path
from pprint import pformat
from typing import Any

from shared.python.utils.metrics import MetricType


DATA_ALGO_2_CLIENT_FOLDER: Path = Path("./data/algo2_client/")
DATA_DPCN_FOLDER: Path = Path("./data/dpcn/")


def assert_field[T](dict: dict[str, Any], field: str, type: type[T]) -> T:
    assert isinstance(dict[field], type), f"Field of not the expected type {type}"
    return dict[field]


@dataclass
class GasData:
    gas_used: int
    request_id: int
    user: str

    def key(self) -> int:
        return self.request_id

    @staticmethod
    def get_gas_data(file: Path) -> dict[int, GasData]:
        data_raw: list[dict[str, str | int]]
        with file.open("r") as f:
            data_raw = json.load(f)

        ret: dict[int, GasData] = {}
        for data_point in data_raw:
            gas_used: int = assert_field(data_point, "gas_used", int)
            request_id: int = assert_field(data_point, "request_id", int)
            user: str = assert_field(data_point, "user", str)
            ret[request_id] = GasData(
                gas_used=gas_used,
                request_id=request_id,
                user=user,
            )

        return ret


@dataclass
class LoadedData:
    client: dict[int, GasData]
    dpcn: dict[int, GasData]


@dataclass
class PreparedData:
    data: list[GasData]

    @property
    def indexes(self) -> list[int]:
        return list(range(1, len(self.data) + 1))

    @property
    def values(self) -> list[int]:
        return [entry.gas_used for entry in self.data]


def load_data() -> LoadedData:
    client_file_upload_data: Path = DATA_ALGO_2_CLIENT_FOLDER / MetricType.A2_CLIENT_FILE_UPLOAD.get_file_name()
    dpcn_file_upload_data: Path = DATA_DPCN_FOLDER / MetricType.A2_DPCN_SERVICED_REQUESTS.get_file_name()

    client_data: dict[int, GasData] = GasData.get_gas_data(client_file_upload_data)
    dpcn_data: dict[int, GasData] = GasData.get_gas_data(dpcn_file_upload_data)

    return LoadedData(
        client=client_data,
        dpcn=dpcn_data,
    )


def prepare_data(loaded_data: LoadedData) -> PreparedData:
    prepared_data: list[GasData] = []

    request_id: int
    client_data_point: GasData
    for request_id, client_data_point in loaded_data.client.items():
        if request_id not in loaded_data.dpcn.keys():
            print(f"Missing entry in DPCN, request_id = \"{request_id}\"")
            continue
        dpcn_data_point: GasData = loaded_data.dpcn[request_id]
        prepared_data.append(GasData(
            gas_used=client_data_point.gas_used + dpcn_data_point.gas_used,
            request_id=request_id,
            user=client_data_point.user,
        ))

    return PreparedData(prepared_data)


def plot_data(data: PreparedData) -> None:
    # Plotting
    plt.figure(figsize=(10, 5))
    plt.plot(data.indexes, data.values, marker='o', linestyle='-', color='blue', label='Y values')

    # Add a horizontal line showing the mean for reference
    mean_y = sum(data.values) / len(data.values)
    plt.axhline(mean_y, color='red', linestyle='--', label=f'Mean = {mean_y:.2f}')

    # Add labels and title
    plt.xlabel('Index')
    plt.ylabel('Value')
    plt.title('Y values vs Index (Showing Constancy)')
    plt.legend()
    plt.grid(True)

    plt.tight_layout()
    plt.show()
    plt.show()



def main():
    loaded_data: LoadedData = load_data()
    prepared_data: PreparedData = prepare_data(loaded_data)
    plot_data(prepared_data)

if __name__ == "__main__":
    main()
