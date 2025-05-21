from __future__ import annotations

import json
import logging
import os

from dataclasses import dataclass
from typing import Self, Any

from eth_account.signers.local import LocalAccount
from eth_typing import Address
from web3 import (
    AsyncWeb3,
    AsyncHTTPProvider,
)
from web3.contract import AsyncContract

from shared.python.evm.algorithms import Algorithm
from shared.python.evm.credentials import get_account


_ALCHEMY_API_URL: str = "https://eth-sepolia.g.alchemy.com/v2/6OBWQixu1j8CsMBXuWFhukd9Zg1YQPot"
_LOCALHOST_URL: str = "http://127.0.0.1:8545"
_BLOCKCHAIN_CONNECTION_URL: str = _LOCALHOST_URL

_CONTRACT_ADDRESS_ENV_VAR_NAME: str = "CONTRACT_ADDRESS"
_CONTRACT_ADDRESS_RAW: str | None = os.environ.get(_CONTRACT_ADDRESS_ENV_VAR_NAME)
assert _CONTRACT_ADDRESS_RAW is not None, f"Did not find env var {_CONTRACT_ADDRESS_ENV_VAR_NAME}"
_CONTRACT_ADDRESS: Address = Address(bytes.fromhex(_CONTRACT_ADDRESS_RAW.lstrip('"').rstrip('"').lstrip("0x")))


@dataclass
class EvmConnection:
    account: LocalAccount
    connection: AsyncWeb3
    contract: AsyncContract

    @classmethod
    async def build_connection(cls, algo: Algorithm, key_index: int) -> Self:
        with open(algo.get_contract_info_file_path()) as contract_info_file:
            _contract_info: dict[str, Any] = json.load(contract_info_file)
            loaded_abi: list[dict] = _contract_info["abi"]

        account: LocalAccount = get_account(key_index)
        connection: AsyncWeb3 = AsyncWeb3(AsyncHTTPProvider(_BLOCKCHAIN_CONNECTION_URL))

        if (await connection.is_connected()) == False:
            logging.error("Failed to connect to the network")
            raise RuntimeError("Could not establish connection")

        contract: AsyncContract = connection.eth.contract(address=_CONTRACT_ADDRESS, abi=loaded_abi)

        return cls(
            account=account,
            connection=connection,
            contract=contract,
        )
