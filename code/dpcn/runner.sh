#!/bin/bash

# Load environment variables
export $(grep -v '^#' ./.env | xargs -0)

# Run the python script
source venv/bin/activate
python3 main.py $@
