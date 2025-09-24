#!/usr/bin/env bash
# tests/smoke_test.sh
set -e
python3 examples/generate_demo_keys.py
# start server in background
python3 src/server.py --port 9000 &
SERVER_PID=$!
sleep 1
# start two clients in background (they will block on stdin; for manual test open terminals)
echo "Server running (pid=${SERVER_PID}). Start clients manually:"
echo "Client 1: python3 src/client.py --connect ws://localhost:9000 --username alice"
echo "Client 2: python3 src/client.py --connect ws://localhost:9000 --username bob"
echo "Kill server with: kill ${SERVER_PID}"
