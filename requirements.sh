#!/bin/bash
# This script installs all external tools required by the CDN-finder Go script
# Make sure you have Go installed and $GOPATH/bin is in your PATH

set -e

echo "[*] Installing subfinder..."
GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "[*] Installing amass..."
sudo apt-get update
sudo apt-get install -y amass

echo "[*] Installing dnsx..."
GO111MODULE=on go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

echo "[*] Installing httpx..."
GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "[*] Installing nuclei..."
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

echo "[*] Installing nuclei-templates..."
nuclei -update-templates

echo "[*] Ensure your PATH includes $HOME/go/bin"
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

echo "[✓] All tools installed successfully!"
