# 🛡️ FortiGate Automation Suite

A modular Python automation framework for FortiGate firewalls — covering address/VIP/policy management, WAN failover monitoring, and an AI-powered CLI agent with log analysis.

---

## 📁 Project Structure

```
fortigate-automation/
├── phase1.py                   # Export addresses & groups
├── phase2.py                   # IP search & duplicate detection
├── phase3.py                   # VIP creation & policy update
├── phase4.py                   # Multi-VIP + VIP group + policy
├── Phase 5.py                  # Safe VIP deletion with rollback
├── Final Phase.py              # WAN failover live monitor
├── AI Agent.py                 # AI-powered CLI assistant + log analysis
├── Multi-Policy.py             # Jinja2 template-based config & HTML reports
│
├── fortigate_api_helper.py     # API helper (used by AI Agent)
├── fortigate_api_helper_v2.py  # Enhanced API helper v2 (used by phases 1–5)
├── error_handler.py            # Central error handling, decorators, recovery
├── logging_config.py           # Syslog + console logging setup
│
├── templates/
│   └── report.html             # Auto-generated HTML traffic report
│
├── result_json/                # Output folder (auto-created)
│   ├── fortigate_data.json
│   ├── phase2_result.json
│   ├── phase3_result.json
│   ├── phase4_lab.json
│   ├── phase5_report.json
│   ├── phase_state.json        # WAN monitor live state
│   └── backups/                # Automatic config backups
│
├── .env.example                # Environment variable template
├── .gitignore
└── README.md
```

---

## ⚙️ Setup

### 1. Clone & Install Dependencies

```bash
git clone https://github.com/your-username/fortigate-automation.git
cd fortigate-automation

pip install requests python-dotenv jinja2
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your FortiGate IP, token, and other settings
```

### 3. Generate API Token on FortiGate

```
System → Administrators → Create New → REST API Admin
```

---

## 🚀 Usage

### Phase 1 — Export Addresses & Groups

```bash
python phase1.py
```

Exports all firewall address objects and address groups to `result_json/fortigate_data.json`.

---

### Phase 2 — IP Search & Duplicate Detection

```bash
python phase2.py
```

- Finds duplicate address objects
- Searches which groups contain a given IP
- Supports bulk input via file (`@ip_list.txt`)

---

### Phase 3 — VIP Creation & Policy Update

```bash
python phase3.py
```

Interactively creates a static-NAT VIP and attaches it to an existing firewall policy. Includes rollback on failure.

---

### Phase 4 — Multi-VIP Lab

```bash
python phase4.py
```

Creates multiple VIPs (HTTP/HTTPS/SSH), groups them into a VIP group, and creates a firewall policy — all in one run.

---

### Phase 5 — Safe VIP Deletion

```bash
# Interactive (lists VIPs, asks which to delete)
python "Phase 5.py"

# Direct
python "Phase 5.py" VIP_HTTP VIP_SSH

# Dry-run (no changes made)
python "Phase 5.py" --dry-run VIP_HTTP

# Skip confirmations
python "Phase 5.py" --force VIP_HTTP
```

Automatically finds and removes all references (VIP groups, policy dstaddr) before deletion. Creates backups before every change.

---

### Final Phase — WAN Failover Monitor

```bash
python "Final Phase.py"
```

Live monitoring loop that checks WAN1/WAN2 interface status every N seconds and automatically switches VIPs when a link goes down. Uses debouncing to avoid flapping.

```
WAN1 UP  → VIP_FAILOVER_WAN1 active
WAN1 DOWN → VIP_FAILOVER_WAN2 active (after DEBOUNCE_COUNT checks)
```

---

### AI Agent — Intelligent CLI Assistant

```bash
# Interactive mode
python "AI Agent.py"

# Single command
python "AI Agent.py" --single "create address for 10.10.10.10"
python "AI Agent.py" --single "show top source IPs from traffic logs"
python "AI Agent.py" --dry-run
```

Accepts Persian or English natural language commands. Uses an LLM to parse intent and translates to FortiGate API calls or log queries.

**Supported operations:**
- `create_address`, `create_vip`, `create_policy`
- `list_addresses`, `list_policies`, `list_vips`
- `query_traffic_logs`, `analyze_logs`, `search_logs`

**Log analysis types:** `summary`, `top_sources`, `top_destinations`, `blocked_traffic`, `security_events`

---

### Multi-Policy / Jinja2 Templates

```bash
python "Multi-Policy.py"
```

Demonstrates Jinja2-based config generation:
- VIP configs from templates
- Policy configs from templates
- Bulk VIP creation from definitions
- HTML traffic analysis report → `templates/report.html`

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FortiGate REST API                   │
└──────────────────────┬──────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          │  fortigate_api_helper   │  ← retry, rate-limit,
          │       _v2.py            │    error handling,
          │                         │    pagination
          └────────────┬────────────┘
                       │
     ┌─────────────────┼──────────────────┐
     │                 │                  │
  phase1-5         Final Phase         AI Agent
  (CRUD)           (Failover)          (LLM + logs)
     │                 │                  │
     └─────────────────┴──────────────────┘
                       │
          ┌────────────┴────────────┐
          │     error_handler.py    │  ← custom exceptions,
          │     logging_config.py   │    decorators, recovery,
          │                         │    backup manager
          └─────────────────────────┘
```

---

## 🔒 Safety Features

| Feature | Description |
|---------|-------------|
| **Backup before change** | Every write operation creates a JSON backup first |
| **Rollback support** | Phase 3, 4, 5 can undo changes if a step fails |
| **Dry-run mode** | `--dry-run` flag simulates operations without touching FortiGate |
| **Debouncing** | WAN monitor waits N consecutive checks before triggering failover |
| **Dangerous keyword filter** | AI Agent blocks destructive requests like "delete all" |
| **Audit log** | AI Agent logs every action to `ai_agent_audit.json` |

---

## 📊 Output Files

| File | Description |
|------|-------------|
| `result_json/fortigate_data.json` | Phase 1 export |
| `result_json/phase2_result.json` | IP search & duplicates |
| `result_json/phase3_result.json` | VIP + policy operation result |
| `result_json/phase4_lab.json` | Multi-VIP lab result |
| `result_json/phase5_report.json` | VIP deletion report |
| `result_json/phase_state.json` | WAN monitor live state |
| `result_json/backups/` | Automatic config snapshots |
| `ai_agent_audit.json` | AI Agent action log |
| `fortigate_logs_cache.json` | Cached FortiGate logs |
| `templates/report.html` | Generated HTML traffic report |

---

## 🧰 Requirements

```
Python >= 3.8
requests
python-dotenv
jinja2
```

```bash
pip install requests python-dotenv jinja2
```

---

## 📝 License

MIT
