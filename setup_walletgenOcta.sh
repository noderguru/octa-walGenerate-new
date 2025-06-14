#!/bin/bash

DIR="/root/octra/wallet_gen-new"
FILE_URL="https://raw.githubusercontent.com/noderguru/octra-walGenerate-new/main/wallet_generator.py"
TMUX_SESSION="octra-walletGenNEW"
PYTHON_FILE="wallet_generator.py"

mkdir -p "$DIR"
cd "$DIR" || exit 1

if [ ! -f "$PYTHON_FILE" ]; then
    echo "[+] Downloading $PYTHON_FILE..."
    wget -q "$FILE_URL" -O "$PYTHON_FILE"
else
    echo "[✓] $PYTHON_FILE already exists"
fi

install_if_missing() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "[+] Installing $1..."
        apt update && apt install -y "$2"
    else
        echo "[✓] $1 is already installed"
    fi
}

install_if_missing python3 python3
install_if_missing python3-venv python3-venv
install_if_missing tmux tmux
install_if_missing ufw ufw
install_if_missing curl curl

if [ ! -d "env" ]; then
    echo "[+] Creating Python virtual environment..."
    python3 -m venv env
else
    echo "[✓] Virtual environment already exists"
fi

if ! tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    echo "[+] Starting tmux session '$TMUX_SESSION'..."
    tmux new-session -d -s "$TMUX_SESSION" "
    cd $DIR && \
    source env/bin/activate && \
    pip install --upgrade pip && \
    pip install pynacl ecdsa flask && \
    python3 $PYTHON_FILE
    "
else
    echo "[✓] tmux session '$TMUX_SESSION' is already running"
fi

ufw allow 8888/tcp > /dev/null

IP=$(curl -s https://api.ipify.org || hostname -I | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+\./) {print $i; exit}}')

# === Final info output ===
echo "✅ Flask wallet is running inside tmux session '$TMUX_SESSION'"
echo "🌐 Open in your browser: http://$IP:8888"
