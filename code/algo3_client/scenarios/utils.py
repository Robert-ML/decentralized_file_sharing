import asyncio
import random
import logging

from typing import Coroutine

from services.file_uploader import FileUploader
from services.file_share_requester import FileShareRequester
from core.file_credentials import FilePrencCredentials
from shared.python.evm.algorithms import Algorithm
from shared.python.evm.connection import EvmConnection
from shared.python.utils.asynckit import create_task_log_on_fail


async def create_uploaders(no_clients: int, index_start: int = 1) -> list[FileUploader]:
    connections: list[EvmConnection] = await get_connections(no_clients, index_start)

    return [
        FileUploader(connection) for connection in connections
    ]

async def create_share_requesters(no_clients: int, index_start: int = 1) -> list[FileShareRequester]:
    connections: list[EvmConnection] = await get_connections(no_clients, index_start)

    return [
        FileShareRequester(connection) for connection in connections
    ]

async def get_connections(no_clients: int, index_start: int) -> list[EvmConnection]:
    # TODO: check if 19 is the correct check and if "index_start +" is correct
    assert index_start + no_clients <= 19, "There are not enough keys to create so many clients, DPCN needs also one"
    connection_tasks: list[Coroutine[None, None, EvmConnection]] = [
        EvmConnection.build_connection(Algorithm.ALGO2, index) for index in range(index_start, no_clients + index_start)
    ]

    return await asyncio.gather(*connection_tasks)
