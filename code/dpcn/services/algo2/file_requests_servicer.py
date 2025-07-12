import asyncio
import logging

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from hexbytes import HexBytes
from typing import Coroutine
from typing_extensions import override

from web3.types import TxReceipt
from shared.python.crypto.prenc.isshiki_2013 import to_int_array

from core.common_vars import CommonVars
from core.db import DB
from core.prenc_identity import PrencIdentity
from services.crypto.prenc_create_identity import create_prenc_identity
from shared.python.evm.force_transact import force_transaction
from shared.python.evm.connection import EvmConnection
from shared.python.utils.asynckit import create_task_log_on_fail
from shared.python.utils.metrics import Metric, MetricsCollector, MetricType


_LISTEN_PERIOD: timedelta = timedelta(seconds=5)


@dataclass
class _FileEncryptionData:
    """
    This contains data that will be sent to the contract
    """
    request_id: int
    user: str
    prenc_identity: PrencIdentity


class FileIdRequestsServicer:
    def __init__(self, evm_connection: EvmConnection) -> None:
        self.__connection: EvmConnection = evm_connection
        self.__pending_responses: asyncio.Queue[_FileEncryptionData] = asyncio.Queue()
        # to not service a user's requests in multiple threads at the same time
        # easier to not support repeating request_ids in a run
        self.__user_requests_being_serviced: dict[str, set[int]] = defaultdict(lambda: set())

        self._metric_file_no: int = 0

    def get_tasks_to_run(self) -> list[Coroutine[None, None, None]]:
        return [
            self.__forever_listen_to_requests(),
            self.__forever_send_request_responses(),
        ]


    async def __forever_listen_to_requests(self) -> None:
        logging.info("Starting forever listen to file requests")
        await asyncio.sleep(_LISTEN_PERIOD.total_seconds())
        while CommonVars().running:
            try:
                await self.__listen_to_requests()
            except Exception as e:
                logging.error(f"Forever listen to requests gave error: {repr(e)}", exc_info=e)
            await asyncio.sleep(_LISTEN_PERIOD.total_seconds())

    async def __listen_to_requests(self) -> None:
        # Note: it would have been nicer to return how many requests each user has
        users_pending_upload: list[str] = await self.__connection.contract.functions.get_users_pending_uploads().call()
        if len(users_pending_upload) == 0:
            return

        logging.info(f"Found {len(users_pending_upload)} users requesting files")

        users_servicers: dict[str, asyncio.Task[None]] = {}
        async with asyncio.TaskGroup() as tg:
            for user in users_pending_upload:
                users_servicers[user] = tg.create_task(self.__service_user(user))

    async def __service_user(self, user: str) -> None:
        requests_ids: list[int] = await self.__connection.contract.functions.get_files_pending_ids_of_user(user).call()
        logging.info(f"User \"{user}\" requested {len(requests_ids)} file credential/s")

        requests_servicers: list[asyncio.Task[None]] = []
        async with asyncio.TaskGroup() as tg:
            for request_id in requests_ids:
                if request_id not in self.__user_requests_being_serviced[user]:
                    requests_servicers.append(tg.create_task(
                        self.__service_file_request(
                            user=user,
                            request_id=request_id
                        )
                    ))
                    self.__user_requests_being_serviced[user].add(request_id)

    async def __service_file_request(self, user: str, request_id: int) -> None:
        # generate the file credentials
        generated_file_identity: PrencIdentity = create_prenc_identity(user)
        completed_request: _FileEncryptionData = _FileEncryptionData(
            request_id=request_id,
            user=user,
            prenc_identity=generated_file_identity,
        )
        await self.__pending_responses.put(completed_request)


    async def __forever_send_request_responses(self) -> None:
        running_tasks: set[asyncio.Future[None]] = set()
        logging.info(f"Starting forever send request responses")
        while CommonVars().running:
            try:
                request_response: _FileEncryptionData = await asyncio.wait_for(self.__pending_responses.get(), timeout=_LISTEN_PERIOD.total_seconds())
                logging.info(
                    f"User \"{request_response.user}\" | id: {request_response.request_id}: sending request response"
                )
                running_tasks.add(create_task_log_on_fail(self.__safe_send_request_response(request_response)))
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                logging.error(f"Forever send request responses gave error: {repr(e)}", exc_info=e)

            # try to clean up some done tasks
            done_tasks: set[asyncio.Future[None]] = set()
            for task in running_tasks:
                if task.done():
                    done_tasks.add(task)

            running_tasks = running_tasks - done_tasks

    async def __safe_send_request_response(self, request_response: _FileEncryptionData) -> None:
        try:
            await self.__send_request_response(request_response)
        except Exception as e:
            logging.error(f"Sending request response failed with error: {repr(e)}", exc_info=e)
            # clean the ID as most probably it did not respond
            self.__user_requests_being_serviced[request_response.user].discard(request_response.request_id)

    async def __send_request_response(self, request_response: _FileEncryptionData) -> None:
        proto_transaction = self.__connection.contract.functions.respond_with_file_id(
            request_id=request_response.request_id,
            generated_file_id=request_response.prenc_identity.id,
            user=request_response.user,
            pp_g=to_int_array(request_response.prenc_identity.public_parameters.g),
            pp_g1=to_int_array(request_response.prenc_identity.public_parameters.g1),
            pp_h=to_int_array(request_response.prenc_identity.public_parameters.h),
            pp_u_v_d=(
                to_int_array(request_response.prenc_identity.public_parameters.u) +
                to_int_array(request_response.prenc_identity.public_parameters.v) +
                to_int_array(request_response.prenc_identity.public_parameters.d)
            ),
            prenc_public_key_pk=(
                to_int_array(request_response.prenc_identity.public_key.pk1) +
                to_int_array(request_response.prenc_identity.public_key.pk2) +
                to_int_array(request_response.prenc_identity.public_key.pk3)
            ),
            prenc_secret_encrypted=[
                request_response.prenc_identity.secret_key.sk1,
                request_response.prenc_identity.secret_key.sk2,
            ] # in production it must be encrypted
        )

        tx_hash: HexBytes = await force_transaction(proto_transaction, self.__connection)

        # print("Waiting for the transaction to be mined...")
        receipt: TxReceipt = await self.__connection.connection.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        # logging.info(f"Transaction receipt:\n" + pformat(receipt, sort_dicts=False))
        gas_used: int = int(receipt["gasUsed"])
        DB().add_identity(request_response.prenc_identity)
        DB().save()
        self._metric_file_no += 1

        # record the metric of how big the file has become
        MetricsCollector.add(_MetricStorageUsedByIdentities(
            file_no=self._metric_file_no,
            bytes_used=DB().get_db_byte_size(),
        ))
        # record the metric of how much gas was used
        MetricsCollector.add(_MetricDPCNRequestResponse(
            user=request_response.user,
            request_id=request_response.request_id,
            gas_used=gas_used,
        ))


# ----------------------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------------------


class _MetricStorageUsedByIdentities(Metric):
    def __init__(self, file_no: int, bytes_used: int) -> None:
        super().__init__(MetricType.A2_DPCN_STORAGE_USED)
        self._file_no: int = file_no
        self._bytes_used: int = bytes_used

    @override
    def get_dict(self) -> dict[str, int | float | str]:
        return {
            "file_no": self._file_no,
            "bytes_used": self._bytes_used,
        }


class _MetricDPCNRequestResponse(Metric):
    def __init__(self, user: str, request_id: int, gas_used: int) -> None:
        super().__init__(MetricType.A2_DPCN_SERVICED_REQUESTS)
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
