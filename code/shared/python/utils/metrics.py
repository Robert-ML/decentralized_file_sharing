from __future__ import annotations
import json
import logging

from abc import ABC, abstractmethod
from collections import defaultdict
from enum import StrEnum
from pathlib import Path

from shared.python.utils.singleton import SingletonMeta


_METRICS_FOLDER: Path = Path("./metrics/")


class MetricType(StrEnum):
    # Algo 2:
    # - DPCN
    A2_DPCN_STORAGE_USED = "algo_2-dpcn-storage_used_by_identities"
    A2_DPCN_SERVICED_REQUESTS = "algo_2-dpcn-serviced_requests"
    A2_DPCN_SHARE_REQUESTS = "algo_2-dpcn-share_requests"

    # - Client
    A2_CLIENT_FILE_UPLOAD = "algo_2-client-file_upload"
    A2_CLIENT_SHARE_REQUEST = "algo_2-client-share_request"


    # Algo 2:
    # - DPCN
    A3_DPCN_SERVICED_REQUESTS = "algo_3-dpcn-serviced_requests"
    A3_DPCN_SHARE_REQUESTS = "algo_3-dpcn-share_requests"

    # - Client
    A3_CLIENT_REGISTER_REQUEST = "algo_3-client-register_request"
    A3_CLIENT_FILE_UPLOAD = "algo_3-client-file_upload"
    A3_CLIENT_SHARE_REQUEST = "algo_3-client-share_request"


    def get_file_name(self) -> str:
        return f"{self.value}.json"


class Metric(ABC):
    def __init__(self, metric: MetricType) -> None:
        self.__metric: MetricType = metric

    @abstractmethod
    def get_dict(self) -> dict[str, int | float | str]:
        pass

    def key(self) -> MetricType:
        return self.__metric

    def get_file_name(self) -> str:
        return self.__metric.get_file_name()


class MetricsCollector(metaclass=SingletonMeta):
    def __init__(self) -> None:
        self._storage: dict[MetricType, list[Metric]] = defaultdict(lambda: [])

    @classmethod
    def set_up(cls) -> None:
        cls()

    @staticmethod
    def add(metric: Metric) -> None:
        self: MetricsCollector = MetricsCollector()
        self._storage[metric.key()].append(metric)

    @staticmethod
    def save() -> None:
        logging.info(f"Saving Metrics Collected")
        self: MetricsCollector = MetricsCollector()

        _METRICS_FOLDER.mkdir(parents=True, exist_ok=True)

        metric_values: list[Metric]
        for metric_values in self._storage.values():
            self._save_metric(metric_values)

        logging.info(f"Metrics Saved")

    def _save_metric(self, metric_values: list[Metric]) -> None:
        # assuming all metrics are the same type
        # nothing to save and not even known where
        if len(metric_values) == 0:
            return

        file_name: str = metric_values[0].get_file_name()
        file_path: Path = _METRICS_FOLDER / file_name

        output_list: list[dict[str, int | float | str]] = []
        for value in metric_values:
            output_list.append(value.get_dict())

        output: str = json.dumps(output_list)

        logging.info(f"Saving metric to file {file_name}")
        with file_path.open("w") as f:
            f.write(output)
