#!/bin/bash

# === Настройки ===
DIR="/root/octra/wallet_gen-new"
FILE_URL="https://raw.githubusercontent.com/noderguru/octa-walGenerate-new/main/wallet_generator.py"
TMUX_SESSION="octa-walletGenNEW"
PYTHON_FILE="wallet_generator.py"

# === Создание директории ===
mkdir -p "$DIR"
cd "$DIR" || exit 1

# === Скачивание wallet_generator.py ===
wget -q "$FILE_URL" -O "$PYTHON_FILE"

# === Проверка наличия python3-venv ===
if ! dpkg -s python3-venv >/dev/null 2>&1; then
    echo "Устанавливаем python3-venv..."
    apt update && apt install -y python3-venv
fi

# === Создание виртуального окружения ===
python3 -m venv env

# === Создание tmux-сессии и запуск всего внутри ===
tmux new-session -d -s "$TMUX_SESSION" "
cd $DIR && \
source env/bin/activate && \
pip install --upgrade pip && \
pip install pynacl ecdsa flask && \
python3 $PYTHON_FILE
"

# === Открытие порта 8888 через UFW ===
ufw allow 8888/tcp > /dev/null

# === Определение внешнего IP ===
IP=$(curl -s https://api.ipify.org || hostname -I | awk '{print $1}')

# === Вывод ссылки ===
echo "✅ Flask кошелёк запущен в tmux-сессии '$TMUX_SESSION'"
echo "🌐 Открой в браузере: http://$IP:8888"
