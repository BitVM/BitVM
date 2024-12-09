#!/bin/bash

pid=`ps | grep "[b]lock-generator" | awk '{print $1}'`
echo "Killing block miner $pid ..."
if [ -n "$pid" ]; then
  kill $pid
else
  echo "block-generator.sh not running"
fi

pid=`docker ps | grep "[b]lockstream/esplora" | awk '{print $1}'`
echo "Stopping esplora client $pid ..."
if [ -n "$pid" ]; then
  docker stop $pid
else
  echo "esplora client not running"
fi