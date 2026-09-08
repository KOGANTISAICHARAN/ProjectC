# Headwaters - Windows Local Setup Guide

## Prerequisites

Install these first (if you don't have them already):

1. **Git** - https://git-scm.com/download/win
2. **Docker Desktop** - https://www.docker.com/products/docker-desktop/ (enable WSL 2 backend during install)

---

## Step 1 - Clone the repo

```powershell
git clone https://github.com/KOGANTISAICHARAN/ProjectC.git
cd ProjectC\headwaters
```

## Step 2 - Start Docker Desktop

Open **Docker Desktop** from the Start Menu and wait until it says **"Docker is running"** (green icon in the system tray).

## Step 3 - Create local env files

```powershell
copy backend\.env.example backend\.env
copy frontend\.env.example frontend\.env
```

## Step 4 - Start the full stack

```powershell
docker compose up --build
```

Wait until you see logs from all services (db, api, web, worker). First build takes a few minutes.

## Step 5 - Verify everything is running

Open a **new terminal** and run:

```powershell
curl http://127.0.0.1:8000/healthz
curl http://127.0.0.1:3100
```

| Service   | URL                        |
|-----------|----------------------------|
| Dashboard | http://127.0.0.1:3100      |
| API       | http://127.0.0.1:8000      |
| API Docs  | http://127.0.0.1:8000/docs |

---

## Step 6 - Load the Chrome Extension

1. Open Chrome and go to `chrome://extensions`
2. Turn on **Developer mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Browse to `ProjectC\headwaters\extension` and select that folder
5. The Headwaters icon appears in the toolbar

### Quick test (no Gmail needed)

Click the Headwaters extension icon -> **Try a sample email**

### Gmail test

Open any email in Gmail -> click **"Check this email"** button in the toolbar.

---

## Useful Commands

```powershell
# Stop the stack (keeps data)
docker compose down

# Stop the stack and delete database
docker compose down -v

# View logs
docker compose logs -f

# Run backend tests
docker compose exec api pytest

# Open database shell
docker compose exec db psql -U headwaters -d headwaters
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `docker compose` not recognized | Make sure Docker Desktop is running. Restart your terminal. |
| Port 8000 or 3100 already in use | Stop the other app, or set custom ports: `$env:API_PORT="8001"; $env:WEB_PORT="3101"; docker compose up --build` |
| Build fails on first try | Run `docker compose down -v` then `docker compose up --build` again |
| Extension not working | Make sure the stack is running first (`http://127.0.0.1:8000/healthz` should return OK) |
