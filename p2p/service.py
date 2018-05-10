import asyncio
import logging  # noqa: F401

from p2p.cancel_token import CancelToken
from p2p.exceptions import OperationCancelled


class BaseService:
    # Subclasses should define their own logger.
    logger = None  # type: logging.Logger
    # Number of seconds stop() waill wait for run() to finish.
    _wait_until_finished_timeout = 2

    def __init__(self, token: CancelToken) -> None:
        self._finished = asyncio.Event()
        self.cancel_token = token

    async def run(self) -> None:
        """Awaits for the subclass' _run() coroutine and sets the _finished event."""
        try:
            await self._run()
        except OperationCancelled as e:
            self.logger.info("%s finished: %s", self, e)
        except Exception:
            self.logger.exception("Unexpected error in %s, exiting", self)
        finally:
            self._finished.set()

    async def stop(self) -> None:
        """Triggers the CancelToken and runs the subclass' _stop() coroutine.

        Also waits for up to _wait_until_finished_timeout seconds for the run() coroutine to
        finish.
        """
        self.cancel_token.trigger()
        await self._stop()
        try:
            await asyncio.wait_for(self._finished.wait(), timeout=self._wait_until_finished_timeout)
        except asyncio.futures.TimeoutError:
            self.logger.info("Timed out waiting for %s to finish, exiting anyway", self)

    #
    # These methods should be implemented by subclasses
    #
    async def _run(self) -> None:
        """Runs the service's loop.

        Should return when the CancelToken is triggered.
        """
        raise NotImplementedError()

    async def _stop(self) -> None:
        raise NotImplementedError()
