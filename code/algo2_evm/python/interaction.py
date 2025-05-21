import asyncio

from pprint import pformat

from eth_account.signers.local import LocalAccount

from web3 import (
    AsyncWeb3,
    AsyncHTTPProvider,
)
from web3.contract import AsyncContract
from web3.middleware import SignAndSendRawMiddlewareBuilder

from utils.my_account import get_account
from contract_constants_algo2_evm import CONTRACT_ADDRESS, CONTRACT_ABI


# Alchemy API URL
ALCHEMY_API_URL = "https://eth-sepolia.g.alchemy.com/v2/6OBWQixu1j8CsMBXuWFhukd9Zg1YQPot"
LOCALHOST_URL = "http://127.0.0.1:8545"
BLOCKCHAIN_CONNECTION_URL = LOCALHOST_URL


FILE_REQUEST_ID: int = 0


async def send_file_upload_request(account: LocalAccount, web3: AsyncWeb3, contract: AsyncContract) -> None:
    # send file upload request
    nonce = await web3.eth.get_transaction_count(account.address, "latest")
    global FILE_REQUEST_ID
    proto_transaction = contract.functions.request_file_upload_info(account.address, FILE_REQUEST_ID)
    FILE_REQUEST_ID += 1

    gas = await proto_transaction.estimate_gas()
    print(f"Estimated gas: {gas}")

    transaction = await proto_transaction.build_transaction({
        "from": account.address,
        "nonce": nonce,
        "gas": gas,
    })
    signed = account.sign_transaction(transaction)
    tx_hash = await web3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"Transaction hash: {tx_hash=}")

    print("Waiting for the transaction to be mined...")
    receipt = await web3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Transaction receipt:\n" + pformat(receipt, sort_dicts=False), end="\n\n")


async def get_users_pending_uploads(contract: AsyncContract) -> list[str]:
    # Interact with the smart contract
    users_pending_upload: list[str] = await contract.functions.get_users_pending_uploads().call()
    return users_pending_upload


async def get_files_pending_ids_of_user(contract: AsyncContract, user: str) -> list[int]:
    pending_ids: list[int] = await contract.functions.get_files_pending_ids_of_user(user).call()
    return pending_ids


async def respond_with_file_id(account: LocalAccount, web3: AsyncWeb3, contract: AsyncContract, request_id: int) -> None:
    nonce = await web3.eth.get_transaction_count(account.address, "latest")
    proto_transaction = contract.functions.respond_with_file_id(request_id, account.address)

    gas = await proto_transaction.estimate_gas()
    print(f"Estimated gas: {gas}")

    transaction = await proto_transaction.build_transaction({
        "from": account.address,
        "nonce": nonce,
        "gas": gas,
    })
    signed = account.sign_transaction(transaction)
    tx_hash = await web3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"Transaction hash: {tx_hash=}")

    print("Waiting for the transaction to be mined...")
    receipt = await web3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Transaction receipt:\n" + pformat(receipt, sort_dicts=False), end="\n\n")


async def main() -> None:
    account: LocalAccount = get_account()
    print(f"Hot wallet address: {account.address}")

    # Connect to the Sepolia network via Alchemy
    web3: AsyncWeb3 = AsyncWeb3(AsyncHTTPProvider(BLOCKCHAIN_CONNECTION_URL))

    # Check if connected
    if (await web3.is_connected()) == False:
        print("Failed to connect to the network")
        return

    contract: AsyncContract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)

    for i in range(2):
        await send_file_upload_request(
            account=account,
            web3=web3,
            contract=contract,
        )

    # print()
    # users_pending: list[str] = await get_users_pending_uploads(
    #     contract=contract,
    # )
    # print(f"{users_pending=}")
    # print()

    # pending_files: list[int] = await get_files_pending_ids_of_user(
    #     contract=contract,
    #     user=users_pending[0],
    # )
    # print(f"{pending_files=}")

    # print()
    # await respond_with_file_id(
    #     account=account,
    #     web3=web3,
    #     contract=contract,
    #     request_id=0,
    # )
    # print()

    # users_pending: list[str] = await get_users_pending_uploads(
    #     contract=contract,
    # )
    # print(f"{users_pending=}")

    # pending_files: list[int] = await get_files_pending_ids_of_user(
    #     contract=contract,
    #     user=users_pending[0],
    # )
    # print(f"{pending_files=}")



if __name__ == "__main__":
    asyncio.run(main())
