import asyncio
import os
import logging
import signal
import sys

from typing import Coroutine

from core.common_vars import CommonVars
from core.db import DB
from services.algo2.file_requests_servicer import FileIdRequestsServicer
from shared.python.evm.algorithms import Algorithm
from shared.python.evm.connection import EvmConnection
from shared.python.utils.print_quicks import get_line
from shared.python.utils.metrics import MetricsCollector


_LOG_DIR: str = f"./logs/"
_LOG_FILE: str = f"dpcn.log"


def setup_logger() -> None:
    if os.path.exists(_LOG_DIR) == False:
        os.makedirs(_LOG_DIR)

    logging.basicConfig(
        filename=_LOG_DIR + _LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s %(filename)s:%(lineno)d [%(levelname)s] %(message)s",
    )


def signal_handler_sigint(sig, frame):
    logging.info(f"SIGINT received, tear down commencing")
    if CommonVars().running == True:
        # it's the first SIGINT, closing gracefully
        CommonVars().running = False
    else:
        logging.error(f"SIGINT received a second time, closing forcefully with clean-up")
        clean_up()
        sys.exit(-1)


def init() -> None:
    setup_logger()
    DB.set_up()
    MetricsCollector.set_up()
    CommonVars.set_up()

    # registering signal handler for clean exit
    signal.signal(signal.SIGINT, signal_handler_sigint)


def clean_up() -> None:
    # save metrics
    MetricsCollector.save()


async def main() -> None:
    init()
    logging.info(f"\n{get_line()}\n\tStarting DPCN\n{get_line()}\n\n")

    connection: EvmConnection = await EvmConnection.build_connection(Algorithm.ALGO2, 0)
    file_request_servicer: FileIdRequestsServicer = FileIdRequestsServicer(connection)

    tasks_to_be_serviced: list[Coroutine[None, None, None]] = []
    tasks_to_be_serviced.extend(file_request_servicer.get_tasks_to_run())

    await asyncio.gather(*tasks_to_be_serviced)

    logging.info(f"\n{get_line()}\n\tDPCN Tearing Down\n{get_line()}\n\n")
    clean_up()
    logging.info(f"\n{get_line()}\n\tDPCN Ended\n{get_line()}\n\n")


if __name__ == "__main__":
    asyncio.run(main())
