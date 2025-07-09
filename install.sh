#!/bin/bash
# =============================================================================
# Installer for Noctua X — Advanced AI-Powered DOM/XHR-Aware XSS Fuzzer
# Compatible with Kali Linux / Debian-based systems
# Author: Haroon Ahmad Awan · CyberZeus
# =============================================================================

set -e

APP_NAME="noctua-x"
VERSION="10.0"
INSTALL_DIR="/opt/$APP_NAME"
VENV_DIR="$INSTALL_DIR/venv"
DEB_DIR="pkg"
DEB_NAME="${APP_NAME}_${VERSION}_all.deb"

echo "[+] Installing required system dependencies..."
sudo apt update
sudo apt install -y \
  python3 python3-pip python3-venv \
  git curl build-essential \
  libffi-dev libssl-dev \
  libxml2-dev libxslt1-dev \
  zlib1g-dev libjpeg-dev \
  chromium-driver chromium \
  fonts-liberation libnss3 libatk-bridge2.0-0 libxss1 \
  libasound2 libxcomposite1 libxrandr2 libgbm1 libgtk-3-0

echo "[+] Creating virtual environment in $VENV_DIR..."
mkdir -p "$INSTALL_DIR"
python3 -m venv "$VENV_DIR"

echo "[+] Activating virtualenv and installing Python packages..."
source "$VENV_DIR/bin/activate"

pip install --upgrade pip
pip install -r requirements.txt || pip install \
  requests \
  beautifulsoup4 \
  fake-useragent \
  torch \
  transformers \
  httpx \
  playwright \
  websocket-client

echo "[+] Installing Playwright browser binaries..."
playwright install chromium || true
playwright install-deps || true

deactivate

echo "[+] Copying Noctua X files to $INSTALL_DIR..."
cp -r . "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/noctua.py"

echo "[+] Creating launcher script at /usr/local/bin/noctua-x..."
cat << EOF | sudo tee "/usr/local/bin/noctua-x" > /dev/null
#!/bin/bash
source "$VENV_DIR/bin/activate"
python3 "$INSTALL_DIR/noctua.py" "\$@"
EOF
chmod +x "/usr/local/bin/noctua-x"

echo "[+] Creating .deb package structure for $APP_NAME..."
rm -rf "$DEB_DIR"
mkdir -p "$DEB_DIR/DEBIAN"
mkdir -p "$DEB_DIR/opt"
cp -r "$INSTALL_DIR" "$DEB_DIR/opt/"
mkdir -p "$DEB_DIR/usr/local/bin"
cp "/usr/local/bin/noctua-x" "$DEB_DIR/usr/local/bin/"

cat << EOF > "$DEB_DIR/DEBIAN/control"
Package: $APP_NAME
Version: $VERSION
Section: pentesting
Priority: optional
Architecture: all
Depends: python3, python3-pip
Maintainer: CyberZeus
Description: Noctua X — AI-powered DOM/XHR-aware XSS Fuzzer with iframe injection, WebSocket sink monitoring, CSP bypass, and beacon logging.
EOF

echo "[+] Building .deb package..."
dpkg-deb --build "$DEB_DIR" "$DEB_NAME"

echo "[✓] Installation complete!"
echo "Run Noctua X with:"
echo "    noctua-x -u http://target --simulate-spa --threads 20"
echo "DEB package created: $DEB_NAME"
