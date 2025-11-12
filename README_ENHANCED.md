# Enhanced Security Agent System

Multi-agent security orchestration system with Threat Intelligence integration and SIEM forensics.

## 🏗️ Architecture

```
┌─────────────┐
│   Alert     │
│   Input     │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────┐
│         PLANNER AGENT                   │
│  • Load playbooks from YAML             │
│  • Match alert to playbook              │
│  • Determine workflow path              │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│    THREAT INTELLIGENCE AGENT            │
│  • Check IPs with AbuseIPDB             │
│  • Check IPs with VirusTotal            │
│  • Check file hashes with VirusTotal    │
│  • Check domains with VirusTotal        │
│  • Set ti_checked = true                │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│    FORENSIC AGENT (SIEM Queries)        │
│  • Execute playbook SIEM queries        │
│  • Query Kibana/Elasticsearch           │
│  • Collect forensic evidence            │
│  • AI-powered analysis (Gemini)         │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│         RESPONSE AGENT                  │
│  • Execute response actions             │
│  • Automated blocking                   │
│  • Manual action recommendations        │
│  • Generate incident report             │
└──────┬──────────────────────────────────┘
       │
       ▼
┌─────────────┐
│   JSON      │
│   Output    │
└─────────────┘
```

## 📁 Project Structure

```
agent-system/
├── core/                          # Core agent modules
│   ├── enhanced_agent_workflow.py # Main workflow orchestrator
│   ├── threat_intelligence_agent.py # TI integration
│   ├── siem_query_agent.py        # Kibana/ES queries
│   └── playbook_loader.py         # YAML playbook loader
│
├── playbooks/                     # YAML playbook definitions
│   ├── brute_force_attack.yml
│   ├── malware_detected.yml
│   ├── web_attack.yml
│   ├── data_exfiltration.yml
│   ├── phishing_attack.yml
│   └── privilege_escalation.yml
│
├── tests/                         # Test scripts
│   ├── test_real_agent.py
│   ├── test_real_kibana.py
│   └── test_agent.py
│
├── config/                        # Configuration
│   └── .env.example
│
├── kibana_collector.py            # Polling-based alert collector
└── README_ENHANCED.md             # This file
```

## 🚀 Features

### 1. **Playbook-Based Response**
- Define incident response playbooks in YAML
- Keywords-based automatic playbook matching
- Customizable workflows per incident type

### 2. **Threat Intelligence Integration**
- **AbuseIPDB**: IP reputation checking (abuse confidence score, country, ISP)
- **VirusTotal**: IP, domain, and file hash analysis
- Automatic IOC extraction from alerts
- Configurable per playbook

### 3. **SIEM Forensic Queries**
- Execute Lucene/KQL queries against Kibana/Elasticsearch
- Parameterized queries with alert data substitution
- Time-range based investigation
- Collect evidence automatically

### 4. **AI-Powered Analysis**
- Google Gemini 2.0 Flash for intelligent analysis
- Automated forensic report generation
- Context-aware recommendations

### 5. **Conditional Workflow**
- `ti_checked` flag controls flow
- Only proceeds to forensics after TI check
- Skips unnecessary steps based on playbook config

## ⚙️ Installation

### 1. Prerequisites
```bash
# Python 3.10+
python --version

# Install dependencies
pip install requests pyyaml langgraph langchain langchain-core langchain-google-genai
```

### 2. Configuration
```bash
# Copy example config
cp config/.env.example config/.env

# Edit with your API keys
notepad config/.env
```

Required API Keys:
- **Google Gemini**: https://makersuite.google.com/app/apikey (FREE)
- **AbuseIPDB**: https://www.abuseipdb.com/api (FREE tier: 1,000 checks/day)
- **VirusTotal**: https://www.virustotal.com/gui/user/YOUR_USER/apikey (FREE tier: 500 requests/day)

### 3. Test Installation
```bash
# Test playbook loading
python core/playbook_loader.py

# Test TI agent
python core/threat_intelligence_agent.py

# Test SIEM queries
python core/siem_query_agent.py

# Test full workflow
python core/enhanced_agent_workflow.py
```

## 📖 Usage

### Basic Usage
```python
from core.enhanced_agent_workflow import process_alert

alert = {
    "id": "alert-123",
    "timestamp": "2025-11-12T00:00:00Z",
    "kibana.alert.severity": "high",
    "rule": {
        "name": "Suspicious Activity Detected",
        "description": "Multiple failed login attempts"
    },
    "source": {"ip": "192.168.1.100"},
    "destination": {"ip": "10.0.0.5"}
}

# Process through workflow
result = process_alert(alert)

# Result is JSON with complete analysis
print(json.dumps(result, indent=2))
```

### With Kibana Collector
```powershell
# Load environment variables
$env:GOOGLE_API_KEY = "your_key"
$env:ABUSEIPDB_API_KEY = "your_key"
$env:VIRUSTOTAL_API_KEY = "your_key"

# Run collector with processing
python kibana_collector.py `
    --url https://10.8.0.13:5601 `
    --username elastic `
    --password "your_password" `
    --no-verify `
    --process
```

## 📋 Playbook Format

```yaml
name: "Brute Force Attack Response"
description: "Respond to brute force authentication attempts"
severity: high
keywords:
  - "brute force"
  - "failed login"
  - "authentication"

workflow:
  - triage_agent
  - network_agent
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
  - name: "Recent login attempts from source IP"
    query: "source.ip:{source_ip} AND event.category:authentication"
    timerange: "24h"
  
  - name: "Successful logins from source IP"
    query: "source.ip:{source_ip} AND event.outcome:success"
    timerange: "7d"

actions:
  - action: "Block source IP at firewall"
    priority: critical
    automated: true
  
  - action: "Review authentication logs"
    priority: high
    automated: false

response:
  containment:
    - "Block source IP"
    - "Disable compromised accounts"
  
  eradication:
    - "Reset passwords"
    - "Update authentication policies"
  
  recovery:
    - "Monitor for additional attempts"
    - "Verify account access"
```

## 🔄 Workflow Flow

1. **Alert Received** → Planner Agent
2. **Planner Agent** → Match to Playbook → Set `ti_checked = false`
3. **Router** → Check if TI needed?
   - YES → **TI Agent** (check AbuseIPDB, VirusTotal) → Set `ti_checked = true`
   - NO → Skip to step 4
4. **Router** → Check if `ti_checked == true`?
   - YES → **Forensic Agent** (SIEM queries, Gemini analysis)
   - NO → Wait for TI check
5. **Forensic Agent** → Execute SIEM queries → AI analysis
6. **Response Agent** → Execute actions → Generate report
7. **Output JSON** → Complete results

## 📊 Output Format

```json
{
  "timestamp": "2025-11-12T04:00:00.000Z",
  "alert": {
    "id": "alert-123",
    "rule_name": "Brute Force Detected",
    "severity": "high",
    "timestamp": "2025-11-12T03:59:00.000Z"
  },
  "playbook": {
    "id": "brute_force_attack",
    "name": "Brute Force Attack Response",
    "confidence": 0.85
  },
  "threat_intelligence": {
    "ti_checked": true,
    "overall_verdict": "malicious",
    "ips": [
      {
        "ip": "192.168.1.100",
        "abuseipdb": {
          "success": true,
          "data": {
            "abuse_confidence_score": 85,
            "country_code": "CN",
            "total_reports": 45
          },
          "verdict": "malicious"
        },
        "virustotal": {
          "success": true,
          "data": {
            "malicious": 8,
            "suspicious": 2
          },
          "verdict": "malicious"
        },
        "verdict": "malicious"
      }
    ]
  },
  "siem_investigation": {
    "queries": [
      {
        "name": "Recent login attempts from source IP",
        "total_hits": 145,
        "results": [...]
      }
    ]
  },
  "forensic_analysis": {
    "key_findings": [
      "Multiple failed SSH login attempts",
      "Source IP has high abuse score"
    ],
    "attack_timeline": [...],
    "iocs": [...]
  },
  "response_actions": [
    "[AUTO] Block source IP at firewall (Priority: critical)",
    "[MANUAL] Review authentication logs (Priority: high)"
  ]
}
```

## 🔧 Troubleshooting

### Issue: TI checks failing
```bash
# Check API keys
echo $env:ABUSEIPDB_API_KEY
echo $env:VIRUSTOTAL_API_KEY

# Test TI agent directly
python core/threat_intelligence_agent.py
```

### Issue: SIEM queries returning no results
```bash
# Check Kibana credentials
echo $env:KIBANA_URL
echo $env:KIBANA_USERNAME

# Test SIEM agent directly
python core/siem_query_agent.py
```

### Issue: Playbooks not loading
```bash
# Check playbooks directory
ls playbooks/

# Test playbook loader
python core/playbook_loader.py
```

## 📝 Creating Custom Playbooks

1. Create new YAML file in `playbooks/` directory
2. Follow the format in existing playbooks
3. Define keywords for matching
4. Configure TI checks needed
5. Add SIEM queries with parameters
6. Define response actions

Example:
```yaml
name: "Custom Incident Response"
description: "My custom playbook"
severity: medium
keywords:
  - "custom keyword"
  - "specific indicator"

threat_intelligence:
  check_ip: true
  check_domain: false
  check_hash: false

siem_queries:
  - name: "Custom Query"
    query: "custom.field:{source_ip}"
    timerange: "1h"

actions:
  - action: "Custom action"
    priority: high
    automated: false
```

## 🎯 Best Practices

1. **API Rate Limits**:
   - AbuseIPDB Free: 1,000 checks/day
   - VirusTotal Free: 500 requests/day
   - Use caching for repeated IOC checks

2. **SIEM Query Performance**:
   - Use specific time ranges
   - Limit result size
   - Add indexes to query filters

3. **Playbook Design**:
   - Clear, specific keywords
   - Prioritized actions
   - Realistic automation flags

4. **Security**:
   - Store API keys in `.env` file
   - Never commit `.env` to Git
   - Use RBAC for Kibana access

## 📞 Support

For issues or questions, check:
- Logs in `*.log` files
- Collected alerts in `collected_alerts/`
- Agent results in `agent_results/`

---

**Author**: Sp4c3K  
**Version**: 2.0  
**Last Updated**: 2025-11-12
