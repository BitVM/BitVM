#!/bin/bash

echo "Downloading esplora docker container ..."
docker pull blockstream/esplora:latest

printf "\n\n"

read -p "Enter directory path for esplora data [.]: " data_path
data_path=${data_path:-.}
echo "$data_path" > "./data_path"
