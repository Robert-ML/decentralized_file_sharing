#bin/bash

cd ./algo3_client
echo "Starting Client Algo3 service"
gnome-terminal -- bash -c "./runner.sh &> ./logs/runner.log"

sleep 1

echo "Displaying logs of the Client Algo3 service"
gnome-terminal -- bash -c "tail -n 20 -f ./logs/client.log"
