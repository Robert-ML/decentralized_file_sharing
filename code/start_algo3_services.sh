#bin/bash

# ; exec bash

cd ./algo3_evm
echo "Starting EVM Node"
gnome-terminal -- bash -c "npx hardhat node"
sleep 5

echo "Deploying Algo 3 evm contract"
gnome-terminal -- bash -c "npx hardhat ignition deploy ./ignition/modules/main.ts --network localhost"
sleep 5


cd ../dpcn

echo "Starting DPCN service - Algo 3"
gnome-terminal -- bash -c "./runner.sh 3 &> ./logs/runner.log"
sleep 1

echo "Displaying logs of the DPCN service"
gnome-terminal -- bash -c "tail -n 20 -f ./logs/dpcn.log"
