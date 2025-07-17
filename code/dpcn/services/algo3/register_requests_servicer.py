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
from shared.python.crypto.utils import get_random_int
from shared.python.evm.force_transact import force_transaction
from shared.python.evm.connection import EvmConnection
from shared.python.utils.asynckit import create_task_log_on_fail
from shared.python.utils.metrics import Metric, MetricsCollector, MetricType


_LISTEN_PERIOD: timedelta = timedelta(seconds=5)


@dataclass
class _RegistrationData:
    """
    This contains data that will be sent to the contract
    """
    user: str
    dpcn_pk: int


class RegisterRequestsServicer:
    def __init__(self, evm_connection: EvmConnection) -> None:
        self.__connection: EvmConnection = evm_connection
        self.__pending_responses: asyncio.Queue[_RegistrationData] = asyncio.Queue()

        self.__user_requests_being_serviced: set[str] = set()
        self._metric_file_no: int = 0

    def get_tasks_to_run(self) -> list[Coroutine[None, None, None]]:
        return [
            self.__forever_listen_to_requests(),
            self.__forever_send_request_responses(),
        ]


    async def __forever_listen_to_requests(self) -> None:
        logging.info("Starting forever listen to registration requests")
        await asyncio.sleep(_LISTEN_PERIOD.total_seconds())
        while CommonVars().running:
            try:
                await self.__listen_to_requests()
            except Exception as e:
                logging.error(f"Forever listen to registration requests gave error: {repr(e)}", exc_info=e)
            await asyncio.sleep(_LISTEN_PERIOD.total_seconds())

    async def __listen_to_requests(self) -> None:
        # Note: it would have been nicer to return how many requests each user has
        users_pending_registration: list[str] = await self.__connection.contract.functions.get_users_pending_registration().call()
        if len(users_pending_registration) == 0:
            return

        logging.info(f"Found {len(users_pending_registration)} users requesting files")

        users_servicers: dict[str, asyncio.Task[None]] = {}
        async with asyncio.TaskGroup() as tg:
            for user in users_pending_registration:
                users_servicers[user] = tg.create_task(self.__service_user(user))

    async def __service_user(self, user: str) -> None:
        if user in self.__user_requests_being_serviced:
            return

        dpcn_pk: int = get_random_int()
        await self.__pending_responses.put(
            _RegistrationData(
                user=user,
                dpcn_pk=dpcn_pk,
            )
        )

        self.__user_requests_being_serviced.add(user)



    async def __forever_send_request_responses(self) -> None:
        running_tasks: set[asyncio.Future[None]] = set()
        logging.info(f"Starting forever send registration request responses")
        while CommonVars().running:
            try:
                request_response: _RegistrationData = await asyncio.wait_for(self.__pending_responses.get(), timeout=_LISTEN_PERIOD.total_seconds())
                logging.info(
                    f"User \"{request_response.user}\": sending registration request response"
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

    async def __safe_send_request_response(self, request_response: _RegistrationData) -> None:
        try:
            await self.__send_request_response(request_response)
        except Exception as e:
            logging.error(f"Sending request response failed with error: {repr(e)}", exc_info=e)
            # clean the ID as most probably it did not respond
            self.__user_requests_being_serviced.discard(request_response.user)

    async def __send_request_response(self, request_response: _RegistrationData) -> None:
        proto_transaction = self.__connection.contract.functions.respond_with_registration(
            user=request_response.user,
            dpcn_pk=request_response.dpcn_pk,
        )

        tx_hash: HexBytes = await force_transaction(proto_transaction, self.__connection)

        # print("Waiting for the transaction to be mined...")
        receipt: TxReceipt = await self.__connection.connection.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        # logging.info(f"Transaction receipt:\n" + pformat(receipt, sort_dicts=False))
        gas_used: int = int(receipt["gasUsed"])
        self._metric_file_no += 1

        # record the metric of how much gas was used
        MetricsCollector.add(_MetricDPCNRequestResponse(
            user=request_response.user,
            request_no=self._metric_file_no,
            gas_used=gas_used,
        ))


# ----------------------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------------------


class _MetricDPCNRequestResponse(Metric):
    def __init__(self, user: str, request_no: int, gas_used: int) -> None:
        super().__init__(MetricType.A3_DPCN_SERVICED_REQUESTS)
        self._user: str = user
        self._request_no: int = request_no
        self._gas_used: int = gas_used

    @override
    def get_dict(self) -> dict[str, int | float | str]:
        return {
            "user": self._user,
            "request_no": self._request_no,
            "gas_used": self._gas_used,
        }
