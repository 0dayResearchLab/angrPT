#!/bin/bash

driver=$1
address=$2
dirpath="result/$(basename $driver .sys)"
logpath="result/$(basename $driver .sys)/angrPT.log"

echo "Driver Name: $driver"
echo "User Static Address: $address"
echo "Log file path: $logpath"
mkdir -p "$dirpath"

python3 ./angrpt.py -d $driver --user-static $address | tee $logpath