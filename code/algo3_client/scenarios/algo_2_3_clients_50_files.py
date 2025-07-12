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


@dataclass
class ShareRequestInfo:
    file_owner: ChecksumAddress
    file_creds: FilePrencCredentials


async def algo_2_3_clients_50_files(make_share_request: bool = False) -> None:
    NO_UPLOADERS: int = 2
    logging.info(f"Starting 2 clients and each uploading 50 files")
    file_uploaders: list[FileUploader] = await create_uploaders(NO_UPLOADERS, 1)

    file_uploading_tasks: list[asyncio.Future[list[ShareRequestInfo]]] = []

    for uploader in file_uploaders:
        file_uploading_tasks.append(
            create_task_log_on_fail(_make_file_uploads(50, uploader))
        )

    logging.info(f"Servicing the clients")
    share_request_info: list[list[ShareRequestInfo]] = await asyncio.gather(*file_uploading_tasks)
    logging.info(f"Done servicing the clients")

    if make_share_request:
        await _make_share_request(
            share_info=list(itertools.chain(*share_request_info)),
            uploaders_no=NO_UPLOADERS,
        )


async def _make_file_uploads(no_uploads: int, uploader: FileUploader) -> list[ShareRequestInfo]:
    servicing_tasks: asyncio.Future = create_task_log_on_fail(
        asyncio.gather(*uploader.get_tasks_to_run())
    )

    upload_requests: list[asyncio.Future[FilePrencCredentials | None]] = []

    for _ in range(no_uploads):
        upload_requests.append(create_task_log_on_fail(
            uploader.generate_upload_file()
        ))

        await asyncio.sleep(random.uniform(1.0, 4.0))

    file_creds: list[FilePrencCredentials | None] = await asyncio.gather(*upload_requests)
    servicing_tasks.cancel()

    share_info: list[ShareRequestInfo] = []
    for cred in file_creds:
        if cred is None:
            continue
        share_info.append(ShareRequestInfo(uploader.address, cred))

    return share_info

async def _make_share_request(share_info: list[ShareRequestInfo], uploaders_no: int) -> None:
    share_requester: FileShareRequester = (await create_share_requesters(1, 1 + uploaders_no))[0]

    servicing_tasks: asyncio.Future = create_task_log_on_fail(
        asyncio.gather(*share_requester.get_tasks_to_run())
    )

    for info in share_info:
        await share_requester.create_file_share_request(
            file_owner_address=info.file_owner,
            file_details=info.file_creds,
        )

    servicing_tasks.cancel()
