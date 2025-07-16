import asyncio
import itertools
import random
import logging

from dataclasses import dataclass
from typing import Coroutine, cast

from eth_typing import ChecksumAddress

from core.file_credentials import FilePrencCredentials
from scenarios.utils import create_uploaders, create_share_requesters
from services.file_uploader import FileUploader
from services.file_share_requester import FileShareRequester
from shared.python.evm.algorithms import Algorithm
from shared.python.evm.connection import EvmConnection
from shared.python.utils.asynckit import create_task_log_on_fail


async def algo_3_3_clients_50_files(make_share_request: bool = False) -> None:
    NO_UPLOADERS: int = 2
    logging.info(f"Starting 2 clients and each uploading 50 files")
    file_uploaders: list[FileUploader] = await create_uploaders(NO_UPLOADERS, 1)

    file_uploading_tasks: list[asyncio.Future[list[int]]] = []

    for uploader in file_uploaders:
        file_uploading_tasks.append(
            create_task_log_on_fail(_make_file_uploads(50, uploader))
        )

    logging.info(f"Servicing the clients")
    share_request_info: list[list[int]] = await asyncio.gather(*file_uploading_tasks)
    logging.info(f"Done servicing the clients")

    if make_share_request:
        await _make_share_request(
            uploaded_file_ids=list(itertools.chain(*share_request_info)),
            uploaders_no=NO_UPLOADERS,
        )


async def _make_file_uploads(no_uploads: int, uploader: FileUploader) -> list[int]:
    upload_requests: list[asyncio.Future[int]] = []

    for _ in range(no_uploads):
        upload_requests.append(create_task_log_on_fail(
            uploader.generate_upload_file()
        ))

        await asyncio.sleep(random.uniform(1.0, 4.0))

    uploaded_file_ids: list[int] = await asyncio.gather(*upload_requests)
    return uploaded_file_ids


async def _make_share_request(uploaded_file_ids: list[int], uploaders_no: int) -> None:
    share_requester: FileShareRequester = (await create_share_requesters(1, 1 + uploaders_no))[0]

    servicing_tasks: asyncio.Future = create_task_log_on_fail(
        asyncio.gather(*share_requester.get_tasks_to_run())
    )

    for uploaded_file_id in uploaded_file_ids:
        await share_requester.create_file_share_request(
            file_id=uploaded_file_id
        )

    servicing_tasks.cancel()
