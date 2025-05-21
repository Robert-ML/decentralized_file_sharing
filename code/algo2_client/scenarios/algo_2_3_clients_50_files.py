import asyncio
import random
import logging

from typing import Coroutine

from services.file_uploader import FileUploader
from shared.python.evm.algorithms import Algorithm
from shared.python.evm.connection import EvmConnection
from shared.python.utils.asynckit import create_task_log_on_fail

async def algo_2_3_clients_50_files() -> None:
    logging.info(f"Starting 2 clients and each uploading 50 files")
    file_uploaders: list[FileUploader] = await _create_uploaders(2)

    file_uploading_tasks: list[asyncio.Future[None]] = []

    for uploader in file_uploaders:
        file_uploading_tasks.append(
            create_task_log_on_fail(_make_file_uploads(50, uploader))
        )

    logging.info(f"Servicing the clients")
    await asyncio.gather(*file_uploading_tasks)
    logging.info(f"Done servicing the clients")


async def _make_file_uploads(no_uploads: int, uploader: FileUploader) -> None:
    servicing_tasks: asyncio.Future = create_task_log_on_fail(
        asyncio.gather(*uploader.get_tasks_to_run())
    )

    upload_requests: list[asyncio.Future[None]] = []

    for _ in range(no_uploads):
        upload_requests.append(create_task_log_on_fail(
            uploader.generate_upload_file()
        ))

        await asyncio.sleep(random.uniform(1.0, 4.0))

    await asyncio.gather(*upload_requests)
    servicing_tasks.cancel()


async def _create_uploaders(no_clients: int) -> list[FileUploader]:
    assert no_clients <= 19, "There are not enough keys to create so many clients, DPCN needs also one"
    connection_tasks: list[Coroutine[None, None, EvmConnection]] = [
        EvmConnection.build_connection(Algorithm.ALGO2, index) for index in range(1, no_clients + 1)
    ]

    connections: list[EvmConnection] = await asyncio.gather(*connection_tasks)

    return [
        FileUploader(connection) for connection in connections
    ]
