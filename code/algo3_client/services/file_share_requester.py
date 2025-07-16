import asyncio
import logging
import secrets

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from functools import partial
from hexbytes import HexBytes
from pprint import pformat
from typing import Coroutine
from typing_extensions import override

from eth_account.datastructures import SignedTransaction
from eth_typing import ChecksumAddress
from web3.types import Nonce, TxParams, TxReceipt
from shared.python.crypto.prenc.isshiki_2013 import to_int_array

from py_ecc.fields import (
    bn128_FQ12 as FQ12,
)

from core.common_vars import CommonVars
from core.file_credentials import FilePrencCredentials
from shared.python.crypto.prenc.encryptor import PrencEncryptor
from shared.python.crypto.prenc.isshiki_2013 import Isshiki_PrivateKey, Isshiki_PublicParameters, Isshiki_Cyphertext_LV2
from shared.python.evm.force_transact import force_transaction
from shared.python.evm.connection import EvmConnection
from shared.python.utils.asynckit import create_task_log_on_fail
from shared.python.utils.metrics import Metric, MetricsCollector, MetricType


_LISTEN_PERIOD: timedelta = timedelta(seconds=5)


class FileShareRequester:
    def __init__(self, evm_connection: EvmConnection):
        self.__connection: EvmConnection = evm_connection

    def get_tasks_to_run(self) -> list[Coroutine[None, None, None]]:
        return [
            self.__forever_listen_for_serviced_share_requests()
        ]

    async def create_file_share_request(self, file_id: int) -> None:
        logging.info(f"Client \"{self.__connection.account.address}\" requesting share of file with ID: {file_id}")

        gas_used: int = await self.__send_file_share_request(
            file_id=file_id,
        )

        MetricsCollector.add(_MetricClientShareRequest(
            user=self.__connection.account.address,
            request_id=f"{self.__connection.account.address}|{file_id}",
            gas_used=gas_used,
        ))


    async def __send_file_share_request(self, file_id: int) -> int:
        proto_transaction = self.__connection.contract.functions.request_file_share(
            client=self.__connection.account.address,
            file_id=file_id,
        )

        tx_hash: HexBytes = await force_transaction(proto_transaction, self.__connection)

        receipt: TxReceipt = await self.__connection.connection.eth.wait_for_transaction_receipt(tx_hash, timeout=300.0)
        # logging.info(f"Transaction receipt:\n" + pformat(receipt, sort_dicts=False))
        gas_used: int = int(receipt["gasUsed"])

        return gas_used


    async def __forever_listen_for_serviced_share_requests(self) -> None:
        """
        The smart contract publishes the requests for sharing files that were serviced.
        """
        logging.info("Starting forever listen for serviced share requests")
        await asyncio.sleep(_LISTEN_PERIOD.total_seconds())
        while CommonVars().running:
            try:
                await self.__listen_for_serviced_share_requests()
            except Exception as e:
                logging.error(f"Listening for serviced share request tried to crash with error: {repr(e)}", exc_info=e)
            await asyncio.sleep(_LISTEN_PERIOD.total_seconds())


    async def __listen_for_serviced_share_requests(self) -> None:
        """
        Not important for measuring the performance (used gas) of the system
        """
        pass


# ----------------------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------------------


class _MetricClientShareRequest(Metric):
    def __init__(self, user: str, request_id: str, gas_used: int) -> None:
        super().__init__(MetricType.A3_CLIENT_SHARE_REQUEST)
        self._user: str = user
        self._request_id: str = request_id
        self._gas_used: int = gas_used

    @override
    def get_dict(self) -> dict[str, int | float | str]:
        return {
            "user": self._user,
            "request_id": self._request_id,
            "gas_used": self._gas_used,
        }