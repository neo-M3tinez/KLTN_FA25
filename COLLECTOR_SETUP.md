# 🔍 Kibana Alert Collector - Setup Guide

## 📋 Tổng Quan

**Kibana Alert Collector** là công cụ polling alerts từ Kibana SIEM **KHÔNG CẦN WEBHOOK**!

### Tại sao cần Collector?

❌ **Webhook Problems:**
- Cần Kibana license (Gold/Platinum)
- Phải config connector trong Kibana
- Network issues với firewall

✅ **Collector Benefits:**
- ✅ Hoạt động với FREE/Basic license
- ✅ Không cần config Kibana
- ✅ Chạy từ bất kỳ đâu (chỉ cần access Kibana API)
- ✅ Tự động retry nếu có lỗi
- ✅ Track alerts đã xử lý (không duplicate)

---

## 🚀 Quick Start

### Step 1: Install Dependencies
```powershell
cd C:\Users\Public\github-portfolio\agent-system
pip install requests python-dotenv
```

### Step 2: Create Config File
```powershell
# Copy example config
Copy-Item config.env.example config.env

# Edit config.env
notepad config.env
```

Fill in your Kibana details:
```bash
KIBANA_URL=http://your-kibana:5601
KIBANA_USERNAME=elastic
KIBANA_PASSWORD=your_password
```

### Step 3: Test Connection
```powershell
python kibana_collector.py --url http://localhost:5601 --username elastic --password yourpass --test
```

Expected output:
```
✅ Successfully connected to Kibana
✅ Connection test successful!
```

### Step 4: Start Collecting
```powershell
# Collect alerts only (save to files)
python kibana_collector.py --url http://localhost:5601 --username elastic --password yourpass

# Collect AND process through Agent Planner
python kibana_collector.py --url http://localhost:5601 --username elastic --password yourpass --process
```

---

## 🔐 Authentication Methods

### Method 1: Username/Password (Easiest)
```powershell
python kibana_collector.py `
    --url http://localhost:5601 `
    --username elastic `
    --password changeme
```

### Method 2: API Key (Recommended)
```powershell
# Create API key in Kibana:
# Stack Management → API Keys → Create API key

# Use API key
python kibana_collector.py `
    --url http://localhost:5601 `
    --api-key "VnVhQ2ZHY0JDZGJrU..."
```

### Method 3: Environment Variables
```powershell
# Set environment variables
$env:KIBANA_URL = "http://localhost:5601"
$env:KIBANA_USERNAME = "elastic"
$env:KIBANA_PASSWORD = "changeme"

# Run without arguments
python kibana_collector.py
```

---

## 📊 How It Works

### Architecture:
```
┌─────────────────────────────────────────────────────┐
│                  KIBANA SIEM                        │
│              (Detection Alerts)                     │
└───────────────────┬─────────────────────────────────┘
                    │ REST API
                    ↓
┌─────────────────────────────────────────────────────┐
│            KIBANA ALERT COLLECTOR                   │
│                                                     │
│  1. Poll alerts every 60s                          │
│  2. Check for new alerts                           │
│  3. Normalize alert format                         │
│  4. Track processed alerts                         │
└───────────────────┬─────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
        ↓                       ↓
┌────────────────┐     ┌────────────────┐
│  Save to File  │     │  Agent Planner │
│  (JSON format) │     │  (Process)     │
└────────────────┘     └────────────────┘
```

### Polling Process:

1. **Connect to Kibana**
   ```
   GET /api/status → Test connection
   ```

2. **Query Alerts**
   ```
   POST /s/default/api/detection_engine/signals/search
   {
     "query": {
       "range": {"@timestamp": {"gte": "now-5m"}}
     }
   }
   ```

3. **Normalize Alert**
   ```python
   raw_kibana_alert → normalize_alert() → standard_format
   ```

4. **Check if New**
   ```python
   if alert_id not in processed_alerts:
       process_alert()
       processed_alerts.add(alert_id)
   ```

5. **Process with Agent Planner** (optional)
   ```python
   alert → Agent Planner → Playbook → Actions
   ```

---

## 🎯 Usage Examples

### Example 1: Basic Collection (No Processing)
```powershell
# Just collect and save alerts to files
python kibana_collector.py `
    --url http://localhost:5601 `
    --username elastic `
    --password changeme `
    --interval 30
```

Output:
```
🚀 Starting alert collector (polling every 30s)
✅ Successfully connected to Kibana
🔍 Collecting alerts from Kibana...
Found 3 alerts
✅ Found 3 new alerts
📨 Processing alert: Multiple Failed Login Attempts
💾 Saved alert to collected_alerts/alert_20241112_103045.json
⏳ Waiting 30 seconds...
```

### Example 2: Collect + Process with Agent Planner
```powershell
# Collect and process through Gemini-powered agent system
$env:GOOGLE_API_KEY = "your_gemini_key"

python kibana_collector.py `
    --url http://localhost:5601 `
    --username elastic `
    --password changeme `
    --process
```

Output:
```
🚀 Starting alert collector (polling every 60s)
✅ Successfully connected to Kibana
🔍 Collecting alerts from Kibana...
✅ Found 1 new alerts
📨 Processing alert: Ransomware Activity Detected
🧠 Using Gemini-powered agent planner
🤖 Processing alert through agent planner...

🧠 GEMINI-ENHANCED PLANNER - Analyzing Alert
🧠 Consulting Google Gemini for analysis...
✅ Gemini Analysis Complete:
   Incident Type: Ransomware Attack
   Recommended Playbook: malware_detected
   Confidence: 95%

✅ Alert processed successfully
📚 Playbook: Malware Detection Response
📁 Result saved to: agent_results/result_20241112_103050.json
```

### Example 3: Different Kibana Space
```powershell
# If using custom Kibana space
python kibana_collector.py `
    --url http://localhost:5601 `
    --username elastic `
    --password changeme `
    --space security `
    --process
```

### Example 4: High-Frequency Polling
```powershell
# Poll every 10 seconds for critical environments
python kibana_collector.py `
    --url http://localhost:5601 `
    --api-key "VnVhQ2ZHY0JDZGJrU..." `
    --interval 10 `
    --process
```

---

## 📁 Output Files

### 1. Collected Alerts
```
collected_alerts/
├── alert_20241112_103045_a1b2c3d4.json
├── alert_20241112_103110_e5f6g7h8.json
└── alert_20241112_103145_i9j0k1l2.json
```

**Alert Format:**
```json
{
  "id": "alert-123",
  "timestamp": "2024-11-12T10:30:45Z",
  "kibana.alert.severity": "high",
  "kibana.alert.status": "active",
  "rule": {
    "name": "Multiple Failed Login Attempts",
    "description": "Brute force attack detected",
    "id": "rule-456"
  },
  "source": {"ip": "203.0.113.45"},
  "destination": {"ip": "10.0.0.50"},
  "agent": {"name": "ssh-server-01"},
  "raw": { /* full Kibana alert data */ }
}
```

### 2. Agent Results (if --process used)
```
agent_results/
├── result_20241112_103050.json
├── result_20241112_103115.json
└── result_20241112_103150.json
```

**Result Format:**
```json
{
  "status": "completed",
  "alert_id": "alert-123",
  "playbook": {
    "name": "Brute Force Attack Response",
    "flow": ["triage", "network", "forensic", "response"]
  },
  "analysis": {
    "triage": {"priority": "high", "immediate_action": true},
    "network": {"source_ip": "203.0.113.45", "is_malicious": true},
    "forensic": {"evidence": [...], "iocs": [...]},
    "response": {"actions": ["Block IP", "Enable MFA"]}
  },
  "actions": [
    {"action": "Block source IP", "status": "completed"},
    {"action": "Enforce MFA", "status": "completed"}
  ],
  "confidence": 0.92
}
```

### 3. Processed Alerts Tracking
```
processed_alerts.json
```

Keeps track of already processed alert IDs to prevent duplicates.

---

## ⚙️ Configuration Options

### Command Line Arguments:

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--url` | Yes | - | Kibana URL |
| `--username` | No* | - | Kibana username |
| `--password` | No* | - | Kibana password |
| `--api-key` | No* | - | Kibana API key |
| `--space` | No | default | Kibana space ID |
| `--interval` | No | 60 | Poll interval (seconds) |
| `--process` | No | false | Process with Agent Planner |
| `--test` | No | false | Test connection only |

*One authentication method required

### Environment Variables:

```bash
KIBANA_URL=http://localhost:5601
KIBANA_USERNAME=elastic
KIBANA_PASSWORD=changeme
KIBANA_API_KEY=VnVhQ2ZHY0JD...
GOOGLE_API_KEY=your_gemini_key  # For AI processing
```

---

## 🔧 Troubleshooting

### Error: "Cannot connect to Kibana"
```
❌ Failed to connect to Kibana: 401

Solution:
- Check username/password
- Verify Kibana URL
- Test: curl http://localhost:5601/api/status
```

### Error: "No alerts found"
```
No new alerts found

Possible reasons:
1. No alerts in time range (last 5 minutes)
2. All alerts already processed
3. Wrong Kibana space

Solution:
- Check Kibana UI → Security → Alerts
- Delete processed_alerts.json to reprocess
- Verify --space parameter
```

### Error: "Failed to get alerts: 404"
```
Failed to get alerts: 404

Solution:
- Kibana version may not support Detection Engine API
- Try alternative method (automatically attempted)
- Update Kibana to 7.x or 8.x
```

### Performance Issues
```
Collector is slow / high CPU usage

Solution:
- Increase --interval (default: 60s)
- Reduce time range in query
- Use API key instead of username/password
```

---

## 📊 Monitoring

### Log Files:
```
kibana_collector.log - Main collector logs
agent_system.log - Agent planner logs (if --process)
```

### Check Status:
```powershell
# View collector logs
Get-Content kibana_collector.log -Tail 20 -Wait

# View agent logs
Get-Content agent_system.log -Tail 20 -Wait

# Count collected alerts
(Get-ChildItem collected_alerts/*.json).Count

# Count processed results
(Get-ChildItem agent_results/*.json).Count
```

---

## 🚀 Production Deployment

### Run as Windows Service:

1. **Install NSSM (Non-Sucking Service Manager)**
```powershell
# Download from https://nssm.cc/
# Or use chocolatey:
choco install nssm
```

2. **Create Service**
```powershell
nssm install KibanaCollector "C:\Python\python.exe" "C:\path\to\kibana_collector.py --url http://localhost:5601 --username elastic --password changeme --process"
```

3. **Start Service**
```powershell
nssm start KibanaCollector
```

### Run as Linux Systemd Service:

Create `/etc/systemd/system/kibana-collector.service`:
```ini
[Unit]
Description=Kibana Alert Collector
After=network.target

[Service]
Type=simple
User=security
WorkingDirectory=/opt/agent-system
Environment="KIBANA_URL=http://localhost:5601"
Environment="KIBANA_USERNAME=elastic"
Environment="KIBANA_PASSWORD=changeme"
ExecStart=/usr/bin/python3 kibana_collector.py --process
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable kibana-collector
sudo systemctl start kibana-collector
```

---

## 💡 Best Practices

1. **Use API Key Authentication** (not username/password)
2. **Set appropriate poll interval** (60s for normal, 10s for critical)
3. **Monitor disk space** (alerts saved as JSON files)
4. **Rotate logs** (use logrotate or similar)
5. **Enable Gemini** for intelligent analysis
6. **Set up alerting** on collector failures

---

## 🎯 Use Cases

### Use Case 1: Collect All Alerts for Analysis
```powershell
# Just collect, don't process
python kibana_collector.py --url http://kibana:5601 --username elastic --password changeme
```

### Use Case 2: Automated Incident Response
```powershell
# Process with agent planner for auto-remediation
python kibana_collector.py --url http://kibana:5601 --api-key YOUR_KEY --process
```

### Use Case 3: Development/Testing
```powershell
# Fast polling for testing
python kibana_collector.py --url http://localhost:5601 --username elastic --password changeme --interval 10 --process
```

---

**Built by Sp4c3K** 🔐  
*No webhook? No problem!* 🎯
