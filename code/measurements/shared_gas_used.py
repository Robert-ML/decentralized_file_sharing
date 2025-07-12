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


def indexes(length: int) -> list[int]:
    return list(range(1, length + 1))


def load_client_share_data() -> dict[str, int]:
    client_share_data_file: Path = DATA_ALGO_2_CLIENT_FOLDER / MetricType.A2_CLIENT_SHARE_REQUEST.get_file_name()

    data_raw: list[dict[str, str | int]]
    with client_share_data_file.open("r") as f:
        data_raw = json.load(f)

    ret: dict[str, int] = {}
    for data_point in data_raw:
        gas_used: int = assert_field(data_point, "gas_used", int)
        request_id: str = assert_field(data_point, "request_id", str)
        user: str = assert_field(data_point, "user", str)
        ret[f"{user}|{request_id.split("|")[1]}"] = gas_used

    return ret


def load_dpcn_share_data() -> dict[str, int]:
    dpcn_share_data_file: Path = DATA_DPCN_FOLDER / MetricType.A2_DPCN_SHARE_REQUESTS.get_file_name()

    data_raw: list[dict[str, str | int]]
    with dpcn_share_data_file.open("r") as f:
        data_raw = json.load(f)

    ret: dict[str, int] = {}
    for data_point in data_raw:
        gas_used: int = assert_field(data_point, "gas_used", int)
        uid: int = assert_field(data_point, "file_no", int)
        user: str = assert_field(data_point, "client", str)
        ret[f"{user}|{uid}"] = gas_used

    return ret


def main():
    # load data
    client_share_data: dict[str, int] = load_client_share_data()
    dpcn_share_data: dict[str, int] = load_dpcn_share_data()

    plot_data(
        client_share_data=client_share_data,
        dpcn_share_data=dpcn_share_data,
    )


def plot_data(client_share_data: dict[str, int], dpcn_share_data: dict[str, int]) -> None:

    # Plotting
    plt.figure(figsize=(10, 5))

    plt.plot(indexes(len(client_share_data)), list(client_share_data.values()), marker='o', linestyle='-', color='blue', label='Gas Used by Client During Share Request')
    plt.plot(indexes(len(dpcn_share_data)), list(dpcn_share_data.values()), marker='o', linestyle='-', color='red', label='Gas Used by DPCN During Share Request')


    # Add labels and title
    plt.xlabel('Files Shared')
    plt.ylabel('Gas Used')
    # plt.title('Gas Used vs Number of Files Uploaded (Showing Constancy)')
    plt.legend()
    plt.grid(True)

    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()