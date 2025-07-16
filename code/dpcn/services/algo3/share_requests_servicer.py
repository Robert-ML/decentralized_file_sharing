import asyncio
import logging

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from hexbytes import HexBytes
from pprint import pformat
from typing import Coroutine
from typing_extensions import override

from eth_account.datastructures import SignedTransaction
from web3.types import Nonce, TxParams, TxReceipt
from shared.python.crypto.prenc.isshiki_2013 import to_int_array

from core.common_vars import CommonVars
from core.db import DB
from core.prenc_identity import PrencIdentity
from services.crypto.prenc_create_identity import create_prenc_identity
from shared.python.crypto.prenc.isshiki_2013 import Isshiki_PublicKey, Isshiki_ReEncKey
from shared.python.crypto.prenc.re_encryptor import get_re_encryption_key
from shared.python.crypto.utils import get_random_int
from shared.python.evm.force_transact import force_transaction
from shared.python.evm.connection import EvmConnection
from shared.python.utils.asynckit import create_task_log_on_fail
from shared.python.utils.metrics import Metric, MetricsCollector, MetricType


_LISTEN_PERIOD: timedelta = timedelta(seconds=5)


@dataclass
class _FileShareData:
    """
    This contains data that will be sent to perform the file sharing
    """
    client: str
    file_id: int
    client_accessible_sym_key: int


class A3ShareRequestsServicer:
    def __init__(self, evm_connection: EvmConnection) -> None:
        self.__connection: EvmConnection = evm_connection
        self.__pending_responses: asyncio.Queue[_FileShareData] = asyncio.Queue()
        # to not service a user's requests in multiple threads at the same time
        # easier to not support repeating request_ids in a run
        self.__share_requests_being_serviced: set[tuple[str, int]] = set()

    def get_tasks_to_run(self) -> list[Coroutine[None, None, None]]:
        return [
            self.__forever_listen_to_requests(),
            self.__forever_send_share_request_responses(),
        ]

    async def __forever_listen_to_requests(self) -> None:
        logging.info("Algo 3 - Starting forever listen to share requests")
        await asyncio.sleep(_LISTEN_PERIOD.total_seconds())
        while CommonVars().running:
            try:
                await self.__listen_to_requests()
            except Exception as e:
                logging.error(f"Forever listen to requests Algo 3 gave error: {repr(e)}", exc_info=e)
            await asyncio.sleep(_LISTEN_PERIOD.total_seconds())

    async def __listen_to_requests(self) -> None:
        # Note: it would have been nicer to return how many requests each user has
        clients: list[str]
        file_ids: list[int]
        client_prenc_pks: list[int]

        clients, file_ids = await self.__connection.contract.functions.get_pending_share_requests().call()
        if len(clients) == 0:
            return

        logging.info(f"Found {len(clients)} share requests")

        users_servicers: dict[tuple[str, int], asyncio.Task[None]] = {}
        async with asyncio.TaskGroup() as tg:
            for i in range(len(clients)):
                client: str = clients[i]
                file_id: int = file_ids[i]

                users_servicers[(client, file_id)] = tg.create_task(self.__service_share_request(
                    client=client,
                    file_id=file_id,
                ))
                self.__share_requests_being_serviced.add((client, file_id))


    async def __service_share_request(self, client: str, file_id: int) -> None:
        client_accessible_sym_key: int = get_random_int()

        await self.__pending_responses.put(_FileShareData(
            client=client,
            file_id=file_id,
            client_accessible_sym_key=client_accessible_sym_key,
        ))


    async def __forever_send_share_request_responses(self) -> None:
        running_tasks: set[asyncio.Future[None]] = set()
        logging.info(f"Algo 3 - Starting forever send share request responses")
        while CommonVars().running:
            try:
                request_response: _FileShareData = await asyncio.wait_for(self.__pending_responses.get(), timeout=_LISTEN_PERIOD.total_seconds())
                logging.info(
                    f"Client \"{request_response.client}\" | file_id: {request_response.file_id}: sending share request response"
                )
                running_tasks.add(create_task_log_on_fail(self.__safe_send_share_request_response(request_response)))
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                logging.error(f"Forever send share request Algo 3 responses gave error: {repr(e)}", exc_info=e)

            # try to clean up some done tasks
            done_tasks: set[asyncio.Future[None]] = set()
            for task in running_tasks:
                if task.done():
                    done_tasks.add(task)

            running_tasks = running_tasks - done_tasks


    async def __safe_send_share_request_response(self, request_response: _FileShareData) -> None:
        try:
            await self.__send_request_response(request_response)
        except Exception as e:
            logging.error(f"Sending request response failed with error: {repr(e)}", exc_info=e)
            # clean the ID as most probably it did not respond
            self.__share_requests_being_serviced.discard((request_response.client, request_response.file_id))


    async def __send_request_response(self, request_response: _FileShareData) -> None:
        proto_transaction = self.__connection.contract.functions.respond_with_client_encrypted_sym_key(
            client=request_response.client,
            file_id=request_response.file_id,
            client_accessible_sym_key=request_response.client_accessible_sym_key,
        )

        tx_hash: HexBytes = await force_transaction(proto_transaction, self.__connection)

        # print("Waiting for the transaction to be mined...")
        receipt: TxReceipt = await self.__connection.connection.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        # logging.info(f"Transaction receipt:\n" + pformat(receipt, sort_dicts=False))
        gas_used: int = int(receipt["gasUsed"])

        # record the metric of how much gas was used
        MetricsCollector.add(_MetricFileShareResponse(
            client=request_response.client,
            file_no=request_response.file_id,
            gas_used=gas_used,
        ))


# ----------------------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------------------


class _MetricFileShareResponse(Metric):
    def __init__(self, client: str, file_no: int, gas_used: int) -> None:
        super().__init__(MetricType.A3_DPCN_SHARE_REQUESTS)
        self._client: str = client
        self._file_no: int = file_no
        self._gas_used: int = gas_used

    @override
    def get_dict(self) -> dict[str, int | float | str]:
        return {
            "client": self._client,
            "file_no": self._file_no,
            "gas_used": self._gas_used,
        }
