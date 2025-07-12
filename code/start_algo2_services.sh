#bin/bash

# ; exec bash

cd ./algo2_evm
echo "Starting EVM Node"
gnome-terminal -- bash -c "npx hardhat node"
sleep 5

echo "Deploying Algo 2 evm contract"
gnome-terminal -- bash -c "npx hardhat ignition deploy ./ignition/modules/main.ts --network localhost"
sleep 5


cd ../dpcn

echo "Starting DPCN service"
gnome-terminal -- bash -c "./runner.sh 2 &> ./logs/runner.log"
sleep 1

echo "Displaying logs of the DPCN service"
gnome-terminal -- bash -c "tail -n 20 -f ./logs/dpcn.log"
