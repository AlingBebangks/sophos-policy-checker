# Sophos Policy Checker — Kali Linux Deployment Guide

## Requirements

- Kali Linux (2023.x or later, x86_64)
- Internet access for the first install
- A Sophos XG/SFOS configuration backup (`.xml` file, exported from the firewall)

---

## Option A — Docker (Recommended)

### 1. Install Docker

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker

# Allow your user to run Docker without sudo
sudo usermod -aG docker $USER
newgrp docker
```

### 2. Clone the repository

```bash
git clone https://github.com/alingbebangks/sophos-policy-checker.git
cd sophos-policy-checker
```

### 3. Build and start

```bash
docker compose up --build -d
```

First build takes ~3–5 minutes (downloads base image + WeasyPrint system libs).

### 4. Open the tool

```
http://localhost:8080
```

Upload your Sophos XG XML backup and the report generates instantly.
Click **⬇ Download PDF** to save the report.

### Useful commands

```bash
# View logs
docker compose logs -f

# Stop
docker compose down

# Rebuild after code changes
docker compose up --build -d
```

---

## Option B — Run directly with Python (no Docker)

### 1. Install system dependencies (WeasyPrint needs these)

```bash
sudo apt update
sudo apt install -y \
  python3 python3-pip python3-venv \
  libpango-1.0-0 libpangocairo-1.0-0 libcairo2 \
  libgdk-pixbuf2.0-0 libffi-dev shared-mime-info \
  fonts-liberation fonts-dejavu-core
```

### 2. Clone and set up

```bash
git clone https://github.com/alingbebangks/sophos-policy-checker.git
cd sophos-policy-checker

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Start the server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Open `http://localhost:8080` in your browser.

To keep it running after closing the terminal:

```bash
nohup uvicorn app.main:app --host 0.0.0.0 --port 8080 &> checker.log &
echo "PID: $!"
```

---

## Accessing from another machine on the network

If you want to reach the tool from a different host (e.g., your Windows machine):

```bash
# Find your Kali IP
ip a | grep 'inet ' | grep -v 127
```

Then open `http://<kali-ip>:8080` from the other machine.

> **Note:** This tool is for internal/authorised use only. Do not expose port 8080 to untrusted networks. If you need remote access, tunnel over SSH:
> ```bash
> ssh -L 8080:localhost:8080 user@kali-host
> ```

---

## Updating

```bash
cd sophos-policy-checker
git pull
docker compose up --build -d   # if using Docker
# or restart uvicorn if running directly
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `docker: command not found` | Run `sudo apt install docker.io` |
| Port 8080 already in use | Change port: edit `docker-compose.yml` → `"8081:8080"` |
| PDF download fails | Ensure the WeasyPrint system libs are installed (Option B) or rebuild Docker image |
| XML parse error | Verify the file is a full **Settings > Backup & Firmware > Export** backup from Sophos XG, not a partial export |
| `permission denied` on Docker socket | Run `sudo usermod -aG docker $USER && newgrp docker` |
