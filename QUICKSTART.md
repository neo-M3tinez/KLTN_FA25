# 🚀 Quick Start Guide - Enhanced Agent System

## ✅ Prerequisites

1. **Python 3.10+** installed
2. **API Keys** obtained:
   - Google Gemini: https://makersuite.google.com/app/apikey
   - AbuseIPDB: https://www.abuseipdb.com/api
   - VirusTotal: https://www.virustotal.com/gui/user/YOUR_USER/apikey
3. **Kibana/Elasticsearch** access

## 📦 Installation (5 minutes)

### Step 1: Install Dependencies
```powershell
cd C:\Users\Public\github-portfolio\agent-system
pip install -r requirements.txt
```

### Step 2: Configure API Keys
```powershell
# Copy example config
copy config\.env.example config\.env

# Edit config with your API keys
notepad config\.env
```

Update these values in `config\.env`:
```bash
# Kibana
KIBANA_URL=https://your-kibana:5601
KIBANA_USERNAME=elastic
KIBANA_PASSWORD=your_password

# AI & Threat Intelligence
GOOGLE_API_KEY=your_gemini_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
VIRUSTOTAL_API_KEY=your_virustotal_key
```

## 🧪 Test the System

### Test 1: Playbooks Loading
```powershell
python core/playbook_loader.py
```
**Expected Output**: List of 6 playbooks loaded

### Test 2: Threat Intelligence
```powershell
# Set API keys
$env:ABUSEIPDB_API_KEY = "your_key"
$env:VIRUSTOTAL_API_KEY = "your_key"

python core/threat_intelligence_agent.py
```
**Expected Output**: TI check results for sample IPs

### Test 3: SIEM Queries
```powershell
$env:KIBANA_USERNAME = "elastic"
$env:KIBANA_PASSWORD = "your_password"

python core/siem_query_agent.py
```
**Expected Output**: Query results from Kibana

### Test 4: Full Workflow
```powershell
$env:GOOGLE_API_KEY = "your_key"
$env:ABUSEIPDB_API_KEY = "your_key"
$env:VIRUSTOTAL_API_KEY = "your_key"

python core/enhanced_agent_workflow.py
```
**Expected Output**: Complete JSON analysis with TI + SIEM results

## 🎯 Process Real Alert

### Option 1: From Kibana Collector
```powershell
# Load all API keys
$env:GOOGLE_API_KEY = "your_gemini_key"
$env:ABUSEIPDB_API_KEY = "your_abuseipdb_key"
$env:VIRUSTOTAL_API_KEY = "your_virustotal_key"

# Run collector with processing
python kibana_collector.py `
    --url https://10.8.0.13:5601 `
    --username elastic `
    --password "AAA@123aaa!@#" `
    --no-verify `
    --process
```

### Option 2: Process Single Alert
```powershell
python tests/test_real_agent.py
```

## 📊 Understanding the Output

The system outputs JSON with 5 main sections:

### 1. Alert Info
```json
{
  "alert": {
    "id": "alert-123",
    "rule_name": "Brute Force Detected",
    "severity": "high"
  }
}
```

### 2. Matched Playbook
```json
{
  "playbook": {
    "id": "brute_force_attack",
    "name": "Brute Force Attack Response",
    "confidence": 0.85
  }
}
```

### 3. Threat Intelligence Results
```json
{
  "threat_intelligence": {
    "ti_checked": true,
    "overall_verdict": "malicious",
    "ips": [
      {
        "ip": "192.168.1.100",
        "abuseipdb": {
          "abuse_confidence_score": 85,
          "verdict": "malicious"
        },
        "virustotal": {
          "malicious": 8,
          "verdict": "malicious"
        }
      }
    ]
  }
}
```

### 4. SIEM Investigation
```json
{
  "siem_investigation": {
    "queries": [
      {
        "name": "Recent login attempts",
        "total_hits": 145,
        "results": [...]
      }
    ]
  }
}
```

### 5. Response Actions
```json
{
  "response_actions": [
    "[AUTO] Block source IP at firewall",
    "[MANUAL] Review authentication logs"
  ]
}
```

## 🔄 Workflow Verification

The workflow follows this sequence:

1. ✅ **Planner** → Match alert to playbook
2. ✅ **TI Agent** → Check IPs/domains/hashes (sets `ti_checked=true`)
3. ✅ **Forensic Agent** → Execute SIEM queries (only after TI check)
4. ✅ **Response Agent** → Generate action plan

**Key Feature**: The system will NOT proceed to forensics until `ti_checked=true`

## 📁 Output Files

All results are saved as JSON:

- **Alerts**: `collected_alerts/alert_TIMESTAMP.json`
- **Agent Results**: `agent_results/result_TIMESTAMP.json`
- **TI Results**: Embedded in agent results JSON
- **SIEM Results**: Embedded in agent results JSON

## 🎨 Customizing Playbooks

### Create New Playbook

1. Create `playbooks/my_custom_playbook.yml`:

```yaml
name: "My Custom Response"
description: "Handle custom security event"
severity: medium
keywords:
  - "my keyword"
  - "custom event"

workflow:
  - triage_agent
  - forensic_agent
  - response_agent

threat_intelligence:
  check_ip: true
  check_domain: false
  check_hash: false
  sources:
    - abuseipdb
    - virustotal

siem_queries:
  - name: "Find related events"
    query: "custom.field:{source_ip}"
    timerange: "24h"

actions:
  - action: "Investigate custom event"
    priority: high
    automated: false
```

2. Test playbook loading:
```powershell
python core/playbook_loader.py
```

3. System will automatically use new playbook when keywords match!

## 🐛 Troubleshooting

### Problem: "Module not found"
```powershell
pip install -r requirements.txt
```

### Problem: "API key invalid"
```powershell
# Check if key is set
echo $env:ABUSEIPDB_API_KEY
echo $env:VIRUSTOTAL_API_KEY

# Reset keys
$env:ABUSEIPDB_API_KEY = "correct_key"
```

### Problem: "Kibana connection failed"
```powershell
# Test connection
curl -k https://10.8.0.13:5601/api/status

# Use --no-verify flag if self-signed cert
python kibana_collector.py --url ... --no-verify
```

### Problem: "No playbooks loaded"
```powershell
# Check playbooks directory
ls playbooks/

# Should see 6 .yml files
```

## 🎓 Next Steps

1. ✅ **Run tests** to verify setup
2. ✅ **Process real alert** from Kibana
3. ✅ **Review JSON output** to understand structure
4. ✅ **Customize playbooks** for your environment
5. ✅ **Integrate with SOAR** platform
6. ✅ **Set up continuous monitoring** with collector

## 📞 Need Help?

- Check logs: `kibana_collector.log`
- Review playbooks: `playbooks/*.yml`
- Test components individually using scripts in `core/`
- Verify API keys in `config/.env`

---

**Ready to go!** 🚀

Start with:
```powershell
python tests/test_real_agent.py
```

This will process a real alert from your Kibana and show the complete TI + SIEM analysis!
