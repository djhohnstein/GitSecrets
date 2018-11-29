#!/usr/bin/env bash

which go
if [$? -eq 1] then
	echo "[ERROR] Could not locate golang executable \"go\"."
	echo "[ERROR] Please install golang and place the executable within your \$PATH"
	exit 1
fi

which trufflehog
if [$? -eq 1] then
	echo "[+] Downloading Trufflehog..."
	go get github.com/dxa4481/truffleHog 
	echo "[+] Trufflehog install complete!"
fi

echo "[+] Installing requirements.txt..."
sudo pip install -r requirements.txt

if [ $? -ne 0 ] then
	echo "[ERROR] Could not successfully install one or more dependencies from requirements.txt"
	exit 1
fi

echo "[+] Installation complete! You're ready to go!"

