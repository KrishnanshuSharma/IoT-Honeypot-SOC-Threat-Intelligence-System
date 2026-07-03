#!/bin/bash

# Export the key to the environment, then run the dashboard
export ABUSE_IPDB_KEY="47dfcec04fee80c2115634c703d04cf2dc68ee623b4b2feb4ea7310bee92dd693bd3e9755f6379c7"
sudo -E python3 /home/adminn/iot_project/dashboard.py
