import asyncio
import logging

from typing import Coroutine

def create_task_log_on_fail[T](coroutine: Coroutine[None, None, T] | asyncio.Future[T]) -> asyncio.Future[T]:
    future: asyncio.Future = asyncio.ensure_future(coroutine)
    future.add_done_callback(_future_done_callback)
    return future


async def _future_done_callback(future: asyncio.Future) -> None:
    if future.cancelled:
        logging.info(f"Future was cancelled \"{future}\"")
        return

    if (e := future.exception()) is not None:
        logging.error(f"Future returned exception {repr(e)} \"{future}\"", exc_info=e)
        return

    future.result()
