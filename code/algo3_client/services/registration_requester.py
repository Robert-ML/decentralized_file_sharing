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
_DEFAULT_FILE_INFO: str = "Metadata"
_DEFAULT_FILE_ADDRESS: str = "youtu.be/dQw4w9WgXcQ"

_FileRequestId = int
_GasUsed = int


class RegistrationRequester:
    def __init__(self, evm_connection: EvmConnection):
        self.__connection: EvmConnection = evm_connection

    @property
    def address(self) -> ChecksumAddress:
        return self.__connection.account.address


    async def register(self) -> None:
        logging.info(f"User \"{self.address}\" requesting registration")

        # check if already registered
        if await self.__check_if_registered() == True:
            logging.info(f"Client {self.address} already registered, skipping registration")
            return

        # send register request
        gas_used: _GasUsed = await self.__send_register_request()

        if CommonVars().running == False:
            return None

        # check if we were registered
        while CommonVars().running:
            if await self.__check_if_registered() == False:
                await asyncio.sleep(_LISTEN_PERIOD.total_seconds())
            else:
                break

        if CommonVars().running == False:
            return None

        MetricsCollector.add(_MetricRegistrationRequest(
            user=self.address,
            gas_used=gas_used,
        ))


    async def __send_register_request(self) -> _GasUsed:
        proto_transaction = self.__connection.contract.functions.request_registration(
            user=self.address,
        )

        tx_hash: HexBytes = await force_transaction(proto_transaction, self.__connection)

        receipt: TxReceipt = await self.__connection.connection.eth.wait_for_transaction_receipt(tx_hash, timeout=300.0)
        # logging.info(f"Transaction receipt:\n" + pformat(receipt, sort_dicts=False))
        gas_used: int = int(receipt["gasUsed"])

        return gas_used


    async def __check_if_registered(self) -> bool:
        return await self.__connection.contract.functions.check_if_registered(
            user=self.address,
        ).call()


# ----------------------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------------------


class _MetricRegistrationRequest(Metric):
    def __init__(self, user: str, gas_used: int) -> None:
        super().__init__(MetricType.A3_CLIENT_REGISTER_REQUEST)
        self._user: str = user
        self._gas_used: int = gas_used

    @override
    def get_dict(self) -> dict[str, int | float | str]:
        return {
            "user": self._user,
            "gas_used": self._gas_used,
        }
