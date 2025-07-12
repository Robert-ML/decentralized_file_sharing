import asyncio
import random
import logging

from services.file_uploader import FileUploader
from services.file_share_requester import FileShareRequester
from core.file_credentials import FilePrencCredentials
from scenarios.utils import create_uploaders, create_share_requesters
from shared.python.utils.asynckit import create_task_log_on_fail


async def testing_scenario() -> None:
    logging.info(f"Starting testing script")
    file_uploader: FileUploader = (await create_uploaders(1, 1))[0]
    share_requester: FileShareRequester = (await create_share_requesters(1, 2))[0]

    servicing_tasks: asyncio.Future = create_task_log_on_fail(
        asyncio.gather(*(
            file_uploader.get_tasks_to_run() + share_requester.get_tasks_to_run()
            ))
    )

    file_creds: FilePrencCredentials | None = await file_uploader.generate_upload_file()
    assert file_creds is not None, "Failed to Upload file"

    await share_requester.create_file_share_request(
        file_owner_address=file_uploader.address,
        file_details=file_creds,
    )

    servicing_tasks.cancel()
