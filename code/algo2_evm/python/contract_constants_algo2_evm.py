import json

CONTRACT_ABI_PATH = "../artifacts/contracts/main.sol/Algo2ProxyReencryption.json"
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

with open(CONTRACT_ABI_PATH) as contract:
    _contract_info = json.load(contract)
    CONTRACT_ABI = _contract_info["abi"]
