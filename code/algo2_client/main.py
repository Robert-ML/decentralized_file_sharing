import asyncio
import os
import logging
import signal
import sys

from typing import Coroutine

from core.common_vars import CommonVars
from scenarios.algo_2_3_clients_50_files import algo_2_3_clients_50_files
from scenarios.testing import testing_scenario
from shared.python.utils.print_quicks import get_line
from shared.python.utils.metrics import MetricsCollector


_LOG_DIR: str = f"./logs/"
_LOG_FILE: str = f"client.log"


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
    MetricsCollector.set_up()
    CommonVars.set_up()

    # registering signal handler for clean exit
    signal.signal(signal.SIGINT, signal_handler_sigint)


def clean_up() -> None:
    # save metrics
    MetricsCollector.save()


async def main() -> None:
    init()
    logging.info(f"\n{get_line()}\n\tStarting Client - Algo 2\n{get_line()}\n\n")
    await asyncio.sleep(5)

    logging.info(f"Starting scenario")

    for i in range(10):
        await algo_2_3_clients_50_files(make_share_request=True)

    # await testing_scenario()
    logging.info(f"Finished scenario")

    logging.info(f"\n{get_line()}\n\tClient Tearing Down\n{get_line()}\n\n")
    clean_up()
    logging.info(f"\n{get_line()}\n\tClient Ended\n{get_line()}\n\n")


if __name__ == "__main__":
    asyncio.run(main())
