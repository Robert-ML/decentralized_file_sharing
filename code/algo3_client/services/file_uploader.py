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


class FileUploader:
    def __init__(self, evm_connection: EvmConnection):
        self.__connection: EvmConnection = evm_connection
        self.__requests_pending: dict[int, asyncio.Future[None]] = {}
        self.__serviced_requests: set[int] = set()

    @property
    def address(self) -> ChecksumAddress:
        return self.__connection.account.address


    def get_tasks_to_run(self) -> list[Coroutine[None, None, None]]:
        return [
            self.__forever_listen_for_serviced_upload_requests()
        ]


    async def generate_upload_file(self) -> FilePrencCredentials | None:
        request_id: _FileRequestId = int.from_bytes(secrets.token_bytes(256 // 8), 'big', signed=False)
        logging.info(f"User \"{self.address}\" requesting to upload file, request_id: {request_id}")

        # send request for file
        request_id: int
        gas_used_in_file_request: _GasUsed
        request_id, gas_used_in_file_request = await self.__send_file_upload_request(request_id)

        if CommonVars().running == False:
            return None

        # wait for the request ID to be serviced by the DPCN and the credentials put on the blockchain
        ready_notification: asyncio.Future[None] = asyncio.Future()
        self.__requests_pending[request_id] = ready_notification
        await ready_notification
        del self.__requests_pending[request_id]

        if CommonVars().running == False:
            return None

        # retrieve the generated credentials
        file_creds: FilePrencCredentials = await self.__get_generated_file_credentials(request_id)

        if CommonVars().running == False:
            return None

        # upload the file
        gas_used_in_upload: _GasUsed = await self.__upload_file(file_creds)

        total_gas_used: int = gas_used_in_file_request + gas_used_in_upload

        logging.info(f"User \"{self.address}\" finished uploading file, request_id: {request_id} | gas used: {total_gas_used}")

        MetricsCollector.add(_MetricClientFileUpload(
            user=self.address,
            request_id=request_id,
            gas_used=total_gas_used,
        ))

        return file_creds


    async def __send_file_upload_request(self, request_id: int) -> tuple[_FileRequestId, _GasUsed]:
        proto_transaction = self.__connection.contract.functions.request_file_upload_info(
            user=self.address,
            request_id=request_id,
        )

        tx_hash: HexBytes = await force_transaction(proto_transaction, self.__connection)

        receipt: TxReceipt = await self.__connection.connection.eth.wait_for_transaction_receipt(tx_hash, timeout=300.0)
        # logging.info(f"Transaction receipt:\n" + pformat(receipt, sort_dicts=False))
        gas_used: int = int(receipt["gasUsed"])

        return (request_id, gas_used)


    async def __get_generated_file_credentials(self, request_id: int) -> FilePrencCredentials:
        file_encryption_details: list[int] = await self.__connection.contract.functions.get_request_id_result(
            user=self.address,
            request_id=request_id,
        ).call()

        return FilePrencCredentials.from_list_of_parameters(file_encryption_details)


    async def __upload_file(self, file_creds: FilePrencCredentials) -> _GasUsed:
        message: int
        formatted_plaintext: FQ12
        cyphertext: Isshiki_Cyphertext_LV2
        message, formatted_plaintext, cyphertext = await asyncio.get_running_loop().run_in_executor(
            executor=CommonVars().executor,
            func=partial(_get_file_and_cyphertext, file_creds)
        )

        proto_transaction = self.__connection.contract.functions.upload_file(
            user=self.address,
            file_id=file_creds.file_id,
            file_info=_DEFAULT_FILE_INFO,
            file_address=_DEFAULT_FILE_ADDRESS,
            cyphertext=cyphertext.to_evm_args(),
        )

        tx_hash: HexBytes = await force_transaction(proto_transaction, self.__connection)

        receipt: TxReceipt = await self.__connection.connection.eth.wait_for_transaction_receipt(tx_hash, timeout=300)

        # logging.info(f"Transaction receipt:\n" + pformat(receipt, sort_dicts=False))
        gas_used: int = int(receipt["gasUsed"])

        return gas_used


    # receive file credentials
    async def __forever_listen_for_serviced_upload_requests(self) -> None:
        """
        The smart contract publishes the requests for users that have been serviced and are pending file upload. Check
        what request IDs are serviced (ready) to continue the upload process.
        """
        logging.info("Starting forever listen for serviced upload requests")
        await asyncio.sleep(_LISTEN_PERIOD.total_seconds())
        while CommonVars().running:
            try:
                await self.__listen_for_serviced_upload_requests()
            except Exception as e:
                logging.error(f"Listening for serviced request IDs tried to crash with error: {repr(e)}", exc_info=e)
            await asyncio.sleep(_LISTEN_PERIOD.total_seconds())

        # cleaning up the waiting file generators
        for pending_request in self.__requests_pending.values():
            pending_request.set_result(None)


    async def __listen_for_serviced_upload_requests(self) -> None:
        serviced_request_ids: list[int] = await self.__connection.contract.functions.get_user_files_pending_upload(
            user=self.address
        ).call()

        for serviced_request_id in serviced_request_ids:
            if serviced_request_id in self.__serviced_requests:
                continue

            if serviced_request_id not in self.__requests_pending:
                logging.warning(f"Serviced request ID {serviced_request_id} was not found in the requests pending solving, not setting it as Done")
                self.__serviced_requests.add(serviced_request_id)
                continue

            self.__requests_pending[serviced_request_id].set_result(None)
            self.__serviced_requests.add(serviced_request_id)

def _get_file_and_cyphertext(file_creds: FilePrencCredentials) -> tuple[int, FQ12, Isshiki_Cyphertext_LV2]:
        message: int = file_creds.encryptor.algo.get_random_int_in_space()
        formatted_plaintext: FQ12 = file_creds.encryptor.algo.prepare_plaintext(message)

        cyphertext: Isshiki_Cyphertext_LV2 = file_creds.encryptor.algo.enc2(
            pki=file_creds.encryptor.public_key,
            message=formatted_plaintext,
        )
        return (message, formatted_plaintext, cyphertext)


# ----------------------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------------------


class _MetricClientFileUpload(Metric):
    def __init__(self, user: str, request_id: int, gas_used: int) -> None:
        super().__init__(MetricType.A2_CLIENT_FILE_UPLOAD)
        self._user: str = user
        self._request_id: int = request_id
        self._gas_used: int = gas_used

    @override
    def get_dict(self) -> dict[str, int | float | str]:
        return {
            "user": self._user,
            "request_id": self._request_id,
            "gas_used": self._gas_used,
        }
