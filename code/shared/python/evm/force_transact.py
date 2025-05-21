import asyncio

from hexbytes import HexBytes

from web3.types import Nonce, TxParams

from shared.python.evm.connection import EvmConnection


_global_transaction_lock: asyncio.Lock = asyncio.Lock()


async def force_transaction(proto_transaction, connection: EvmConnection) -> HexBytes:
    while True:
        try:
            async with _global_transaction_lock:
                gas = await proto_transaction.estimate_gas()
                # print(f"Estimated gas: {gas}")
                nonce: Nonce = await connection.connection.eth.get_transaction_count(
                    account=connection.account.address,
                    block_identifier="latest"
                )
                transaction: TxParams = await proto_transaction.build_transaction({
                    "from": connection.account.address,
                    "nonce": nonce,
                    "gas": gas,
                })
                signed: SignedTransaction = connection.account.sign_transaction(transaction) # type: ignore
                tx_hash: HexBytes = await connection.connection.eth.send_raw_transaction(signed.raw_transaction)
                return tx_hash
                # print(f"Transaction hash: {tx_hash=}")
        except Exception as e:
            pass
