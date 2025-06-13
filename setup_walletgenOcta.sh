#!/bin/bash

DIR="/root/octra/wallet_gen-new"
FILE_URL="https://raw.githubusercontent.com/noderguru/octra-walGenerate-new/main/wallet_generator.py"
TMUX_SESSION="octra-walletGenNEW"
PYTHON_FILE="wallet_generator.py"

mkdir -p "$DIR"
cd "$DIR" || exit 1

wget -q "$FILE_URL" -O "$PYTHON_FILE"

if ! dpkg -s python3-venv >/dev/null 2>&1; then
    echo "Install python3-venv..."
    apt update && apt install -y python3-venv
fi

python3 -m venv env

tmux new-session -d -s "$TMUX_SESSION" "
cd $DIR && \
source env/bin/activate && \
pip install --upgrade pip && \
pip install pynacl ecdsa flask && \
python3 $PYTHON_FILE
"

ufw allow 8888/tcp > /dev/null

IP=$(curl -s https://api.ipify.org || hostname -I | awk '{print $1}')

echo "✅ Flask wallet launched in tmux session '$TMUX_SESSION'"
echo "🌐 Open in browser: http://$IP:8888"
