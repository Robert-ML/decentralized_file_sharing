import asyncio

from pprint import pformat

from eth_account.signers.local import LocalAccount

from web3 import (
    AsyncWeb3,
    AsyncHTTPProvider,
)
from web3.contract import AsyncContract
from web3.middleware import SignAndSendRawMiddlewareBuilder

from shared.python.evm.algorithms import Algorithm
from shared.python.evm.connection import EvmConnection
from contract_constants_algo2_evm import CONTRACT_ADDRESS, CONTRACT_ABI


# Alchemy API URL
ALCHEMY_API_URL = "https://eth-sepolia.g.alchemy.com/v2/6OBWQixu1j8CsMBXuWFhukd9Zg1YQPot"
LOCALHOST_URL = "http://127.0.0.1:8545"
BLOCKCHAIN_CONNECTION_URL = LOCALHOST_URL


FILE_REQUEST_ID: int = 0


async def send_file_upload_request(connection: EvmConnection) -> None:
    # send file upload request
    nonce = await connection.connection.eth.get_transaction_count(connection.account.address, "latest")
    global FILE_REQUEST_ID
    proto_transaction = connection.contract.functions.request_file_upload_info(connection.account.address, FILE_REQUEST_ID)
    FILE_REQUEST_ID += 1

    gas = await proto_transaction.estimate_gas()
    print(f"Estimated gas: {gas}")

    transaction = await proto_transaction.build_transaction({
        "from": connection.account.address,
        "nonce": nonce,
        "gas": gas,
    })
    signed = connection.account.sign_transaction(transaction)
    tx_hash = await connection.connection.eth.send_raw_transaction(signed.raw_transaction)
    print(f"Transaction hash: {tx_hash=}")

    print("Waiting for the transaction to be mined...")
    receipt = await connection.connection.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Transaction receipt:\n" + pformat(receipt, sort_dicts=False), end="\n\n")


async def get_users_pending_uploads(contract: AsyncContract) -> list[str]:
    # Interact with the smart contract
    users_pending_upload: list[str] = await contract.functions.get_users_pending_uploads().call()
    return users_pending_upload


async def get_files_pending_ids_of_user(contract: AsyncContract, user: str) -> list[int]:
    pending_ids: list[int] = await contract.functions.get_files_pending_ids_of_user(user).call()
    return pending_ids


async def respond_with_file_id(connection: EvmConnection, request_id: int) -> None:
    nonce = await connection.connection.eth.get_transaction_count(connection.account.address, "latest")
    proto_transaction = connection.contract.functions.respond_with_file_id(request_id, connection.account.address)

    gas = await proto_transaction.estimate_gas()
    print(f"Estimated gas: {gas}")

    transaction = await proto_transaction.build_transaction({
        "from": connection.account.address,
        "nonce": nonce,
        "gas": gas,
    })
    signed = connection.account.sign_transaction(transaction)
    tx_hash = await connection.connection.eth.send_raw_transaction(signed.raw_transaction)
    print(f"Transaction hash: {tx_hash=}")

    print("Waiting for the transaction to be mined...")
    receipt = await connection.connection.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Transaction receipt:\n" + pformat(receipt, sort_dicts=False), end="\n\n")


async def main() -> None:
    connection: EvmConnection = await EvmConnection.build_connection(Algorithm.ALGO2, 0)
    print(f"Hot wallet address: {connection.account.address}")

    for i in range(2):
        await send_file_upload_request(
            connection=connection,
        )

    print()
    users_pending: list[str] = await get_users_pending_uploads(
        contract=connection.contract,
    )
    print(f"{users_pending=}")
    print()

    pending_files: list[int] = await get_files_pending_ids_of_user(
        contract=connection.contract,
        user=users_pending[0],
    )
    print(f"{pending_files=}")

    print()
    await respond_with_file_id(
        connection=connection,
        request_id=0,
    )
    print()

    users_pending: list[str] = await get_users_pending_uploads(
        contract=connection.contract,
    )
    print(f"{users_pending=}")

    pending_files: list[int] = await get_files_pending_ids_of_user(
        contract=connection.contract,
        user=users_pending[0],
    )
    print(f"{pending_files=}")



if __name__ == "__main__":
    asyncio.run(main())
