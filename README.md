# Nakul — Server Intelligence & Protection Platform

A production-grade monitoring, correlation, and alerting system for cPanel/WHM hosting environments. Deploys with a single command, runs as a systemd service on port 8122, and gracefully handles missing optional services.

## Features

- **Real-time Monitoring** — CPU, memory, disk, load, network, processes
- **Log Analysis** — Parses Apache/LiteSpeed, MySQL, cPanel, CSF, Imunify360, auth logs
- **Intelligent Correlation** — Links events across sources by account, IP, domain
- **Smart Alerting** — Detects brute-force, DDoS, resource abuse, malware, backup failures
- **Incident Management** — Full lifecycle: new → acknowledged → investigating → resolved
- **Human-Readable Output** — Every alert explains what happened, why it matters, and what to do
- **Modular Plugins** — LiteSpeed, CloudLinux, Imunify360, CSF, Backuply, Softaculous, WP Toolkit
- **Optional-Service Aware** — Missing services don't crash the agent
- **Premium Dashboard** — Dark-mode cybersecurity aesthetic with real-time updates
- **Single-Command Deploy** — One bash script installs everything

## Quick Start

### One-Command Installation

```bash
# On your cPanel server (as root):
bash install.sh
```

The installer will:
1. Detect your OS (CentOS/AlmaLinux/CloudLinux)
2. Install Python 3.9+ and dependencies
3. Create system user and directories
4. Deploy application files and virtual environment
5. Generate configuration with admin credentials
6. Install and start the systemd service
7. Print your dashboard URL and login credentials

### Access the Dashboard

```
http://your-server-ip:8122
```

Login with the credentials shown after installation.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Nakul Agent (systemd)                      │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: Collectors    │ Logs, System, Services, cPanel     │
│ Layer 2: Parsers       │ Apache, MySQL, Security, Backup    │
│ Layer 3: Correlation   │ Account/IP/Domain grouping         │
│ Layer 4: Incidents     │ Rule matching, scoring, dedup      │
│ Layer 5: Notifiers     │ Dashboard, Email, Webhook          │
│ Layer 6: Dashboard     │ FastAPI + Jinja2 on port 8122      │
│ Layer 7: Persistence   │ SQLite with WAL mode               │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

Edit `/etc/nakul/nakul.yaml` to customize:

- **Thresholds** — CPU, memory, disk, load alert levels
- **Log paths** — Override default log file locations
- **Plugins** — Enable/disable service integrations
- **Notifications** — Email, webhook delivery settings
- **Scan intervals** — How often to check logs and metrics
- **Retention** — How long to keep event data

## Service Management

```bash
# Status
systemctl status nakul

# Restart
systemctl restart nakul

# View logs
journalctl -u nakul -f

# Health check
curl http://localhost:8122/api/health
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/login` | Authenticate |
| GET | `/api/summary` | Dashboard summary |
| GET | `/api/alerts` | List alerts |
| PUT | `/api/alerts/{id}/acknowledge` | Acknowledge alert |
| GET | `/api/incidents` | List incidents |
| GET | `/api/incidents/{id}` | Incident detail |
| PUT | `/api/incidents/{id}/state` | Update incident state |
| GET | `/api/services` | Service statuses |
| GET | `/api/events` | Query events |
| GET | `/api/snapshots` | System snapshots |
| GET | `/api/stats` | Database statistics |
| GET | `/api/stream` | SSE real-time updates |
| GET | `/api/export/incidents` | Export (JSON/CSV) |

## Development

```bash
# Clone and install
git clone <repo> nakul
cd nakul
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt

# Run locally
python -m nakul.main --debug --port 8122

# Generate a password
python -m nakul.main --generate-password

# Dry run (validate config)
python -m nakul.main --dry-run

# Run tests
python -m pytest tests/ -v
```

## License

MIT License
