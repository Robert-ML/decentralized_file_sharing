import os

from eth_account import Account
from eth_account.signers.local import LocalAccount


def get_account(key_index: int) -> LocalAccount:
    wallet_secret_env_var_name: str = f"WALLET_SECRET_{key_index}"
    private_key: str | None = os.environ.get(wallet_secret_env_var_name)

    assert private_key is not None, f"Failed to obtain {wallet_secret_env_var_name}"

    private_key = private_key.replace('\"', '')

    if private_key.startswith("0x") == False:
        private_key = "0x" + private_key

    return Account.from_key(private_key)
