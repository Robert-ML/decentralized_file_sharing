import os

from eth_account import Account
from eth_account.signers.local import LocalAccount


def get_account() -> LocalAccount:
    private_key: str | None = os.environ.get('WALLET_SECRET')

    assert private_key is not None, "PRIVATE_KEY is not set"

    private_key = private_key.replace('\"', '')

    if private_key.startswith("0x") == False:
        private_key = "0x" + private_key

    return Account.from_key(private_key)
