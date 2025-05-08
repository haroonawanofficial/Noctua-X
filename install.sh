#!/bin/bash
# =============================================================================
# Installer for Noctua XSS AI Fuzzer (Kali Linux / Debian)
# Author: Haroon Ahmad Awan · CyberZeus
# =============================================================================

set -e

APP_NAME="noctua"
VERSION="9.4"
INSTALL_DIR="/opt/$APP_NAME"
VENV_DIR="$INSTALL_DIR/venv"
DEB_DIR="pkg"
DEB_NAME="${APP_NAME}_${VERSION}_all.deb"

echo "[+] Installing required system dependencies..."
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git curl build-essential libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev libjpeg-dev

echo "[+] Creating virtual environment in $VENV_DIR..."
mkdir -p "$INSTALL_DIR"
python3 -m venv "$VENV_DIR"

echo "[+] Activating venv and installing Python packages..."
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

echo "[+] Installing Playwright browser dependencies..."
playwright install chromium || true

deactivate

echo "[+] Copying files to install directory..."
cp -r . "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/noctua.py"

echo "[+] Creating launch script..."
cat << EOF | sudo tee "/usr/local/bin/noctua" > /dev/null
#!/bin/bash
source "$VENV_DIR/bin/activate"
python3 "$INSTALL_DIR/noctua.py" "\$@"
EOF
chmod +x "/usr/local/bin/noctua"

# Optional .deb generation
echo "[+] Creating .deb package structure..."
rm -rf "$DEB_DIR"
mkdir -p "$DEB_DIR/DEBIAN"
mkdir -p "$DEB_DIR/opt"
cp -r "$INSTALL_DIR" "$DEB_DIR/opt/"
mkdir -p "$DEB_DIR/usr/local/bin"
cp "/usr/local/bin/noctua" "$DEB_DIR/usr/local/bin/"

cat << EOF > "$DEB_DIR/DEBIAN/control"
Package: $APP_NAME
Version: $VERSION
Section: pentesting
Priority: optional
Architecture: all
Depends: python3, python3-pip
Maintainer: CyberZeus
Description: Noctua AI-powered XSS Fuzzer for offensive security and fuzzing.
EOF

echo "[+] Building .deb package..."
dpkg-deb --build "$DEB_DIR" "$DEB_NAME"

echo "[✓] Installation complete!"
echo "Run with:  noctua -u http://target --simulate-spa --threads 20"
echo "DEB package created: $DEB_NAME"
