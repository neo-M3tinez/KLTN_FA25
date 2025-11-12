# Security Agent Planner System
**Author:** Sp4c3K  
**Description:** LangGraph-based multi-agent system for automated security incident response

---

## 🎯 Architecture Overview

```
Kibana SIEM Alert
       ↓
[Webhook Receiver]
       ↓
[PLANNER AGENT] ← Matches alert to playbook
       ↓
   ┌───┴───┐
   ↓       ↓
[Playbook Router]
   ↓
   ├─→ [Triage Agent] ─→ Initial assessment
   ├─→ [Network Agent] ─→ Network analysis
   ├─→ [Forensic Agent] ─→ Evidence collection
   ├─→ [Malware Agent] ─→ Malware analysis
   ├─→ [Web App Agent] ─→ Web attack analysis
   ├─→ [Email Agent] ─→ Phishing analysis
   └─→ [Response Agent] ─→ Automated remediation
       ↓
   [Results & Actions]
```

---

## 📚 Playbook System

### Built-in Playbooks:

1. **Brute Force Attack Response**
   - Severity: High, Critical
   - Flow: Triage → Network → Forensic → Response
   - Actions: Block IP, Enforce MFA, Reset passwords

2. **Malware Detection Response**
   - Severity: Critical, High
   - Flow: Triage → Forensic → Malware → Response
   - Actions: Isolate host, Collect IOCs, Deploy EDR

3. **Data Exfiltration Response**
   - Severity: Critical
   - Flow: Triage → Network → Forensic → Response
   - Actions: Block connection, Identify leaked data

4. **Privilege Escalation Response**
   - Severity: High, Critical
   - Flow: Triage → Forensic → Response
   - Actions: Revoke privileges, Audit logs

5. **Web Attack Response**
   - Severity: Medium, High, Critical
   - Flow: Triage → Network → WebApp → Response
   - Actions: Block requests, Update WAF, Patch

6. **Phishing Attack Response**
   - Severity: Medium, High
   - Flow: Triage → Email → Forensic → Response
   - Actions: Block sender, Quarantine emails

---

## 🤖 Agent Details

### 🎯 Planner Agent
**Role:** Central orchestrator  
**Responsibilities:**
- Receives incoming alerts from Kibana
- Analyzes alert content and severity
- Matches alert to appropriate playbook
- Determines agent execution flow
- Routes to first specialist agent

**Decision Logic:**
```python
# Severity matching
if alert_severity in playbook["severity"]: score += 2

# Keyword matching
for indicator in playbook["indicators"]:
    if indicator in alert_text: score += 5

# Confidence threshold
if score >= 3: use_playbook
else: use_default_playbook
```

---

### 🔍 Triage Agent
**Role:** Initial assessment and prioritization  
**Responsibilities:**
- Evaluate alert severity and impact
- Determine if immediate action required
- Estimate potential damage
- Recommend initial response steps

**Output:**
- Priority level
- Impact assessment
- Immediate action flag
- Next recommended steps

---

### 🌐 Network Agent
**Role:** Network traffic and connection analysis  
**Responsibilities:**
- Analyze source/destination IPs
- Check threat intelligence databases
- Evaluate network patterns
- Recommend firewall rules

**Output:**
- IP reputation analysis
- Threat intelligence data
- Connection patterns
- Blocking recommendations

---

### 🔬 Forensic Agent
**Role:** Deep investigation and evidence collection  
**Responsibilities:**
- Collect system artifacts
- Build attack timeline
- Extract Indicators of Compromise (IOCs)
- Preserve evidence chain

**Output:**
- Evidence collection list
- IOC list
- Attack timeline
- Confidence score

---

### 🦠 Malware Agent
**Role:** Specialized malware analysis  
**Responsibilities:**
- Identify malware family
- Analyze malware behavior
- Extract signatures
- Recommend mitigation

**Output:**
- Malware classification
- Behavior analysis
- Signature matches
- Remediation steps

---

### 🌐 Web App Agent
**Role:** Web application attack analysis  
**Responsibilities:**
- Identify attack type (SQLi, XSS, etc.)
- Locate vulnerable endpoints
- Analyze attack payload
- Recommend WAF rules

**Output:**
- Attack classification
- Vulnerable component
- Payload analysis
- WAF recommendations

---

### 📧 Email Agent
**Role:** Email-based threat analysis  
**Responsibilities:**
- Analyze email headers
- Check sender reputation
- Scan for malicious links/attachments
- Recommend quarantine actions

**Output:**
- Sender analysis
- Malicious content count
- Phishing indicators
- Quarantine recommendations

---

### 🚨 Response Agent
**Role:** Automated remediation and actions  
**Responsibilities:**
- Execute remediation actions from playbook
- Log all actions taken
- Verify action completion
- Generate final report

**Output:**
- Actions executed
- Execution status
- Timestamps
- Final incident summary

---

## 🔄 Workflow Execution

### Step-by-Step Flow:

1. **Alert Reception**
   ```
   Kibana → Webhook → Planner Agent
   ```

2. **Playbook Matching**
   ```python
   alert_text = alert_name + alert_description
   for playbook in PLAYBOOKS:
       score = match_severity(alert) + match_keywords(alert_text)
       if score > max_score:
           selected_playbook = playbook
   ```

3. **Agent Chain Execution**
   ```
   For each agent in playbook["flow"]:
       Execute agent
       Store results in state
       Route to next agent
   ```

4. **State Management**
   ```python
   state = {
       "alert": {...},
       "playbook": {...},
       "current_agent": "triage_agent",
       "analysis_results": {},
       "actions_taken": [],
       "confidence": 0.85
   }
   ```

5. **Final Output**
   ```json
   {
       "status": "completed",
       "alert_id": "alert-12345",
       "playbook": "Brute Force Attack Response",
       "agents_executed": 4,
       "actions_taken": 5,
       "confidence": 0.85
   }
   ```

---

## 🚀 Installation & Setup

### 1. Install Dependencies
```bash
cd C:\Users\Public\github-portfolio\agent-system
pip install -r requirements.txt
```

### 2. Set Environment Variables (Optional)
```bash
# If using LLM features
$env:OPENAI_API_KEY = "your-api-key"
```

### 3. Start Webhook Server
```bash
python agent_webhook.py
```

Server will start on `http://0.0.0.0:5000`

---

## 🧪 Testing

### Test with Sample Alert:
```bash
python agent_planner.py
```

This will run an example brute force alert through the system.

### Test via Webhook:
```powershell
$alert = @{
    "id" = "alert-12345"
    "rule" = @{
        "name" = "Multiple Failed Login Attempts"
        "description" = "Brute force attack detected"
    }
    "kibana.alert.severity" = "high"
    "source" = @{"ip" = "192.168.1.100"}
    "destination" = @{"ip" = "10.0.0.50"}
    "timestamp" = (Get-Date).ToString("o")
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:5000/webhook/agent/alert" `
    -Method Post `
    -ContentType "application/json" `
    -Body $alert
```

---

## 🔧 Kibana Integration

### Configure Kibana Webhook Connector:

1. **Go to:** Stack Management → Rules and Connectors → Connectors
2. **Create Webhook:**
   - Name: `Security Agent Planner`
   - URL: `http://YOUR_IP:5000/webhook/agent/alert`
   - Method: `POST`
   - Headers: `Content-Type: application/json`

3. **Connector Body:**
```json
{
  "id": "{{alert.id}}",
  "rule": {
    "name": "{{rule.name}}",
    "description": "{{rule.description}}"
  },
  "kibana.alert.severity": "{{alert.severity}}",
  "kibana.alert.status": "{{alert.status}}",
  "source": {
    "ip": "{{source.ip}}"
  },
  "destination": {
    "ip": "{{destination.ip}}"
  },
  "agent": {
    "name": "{{agent.name}}"
  },
  "timestamp": "{{@timestamp}}"
}
```

4. **Add to Detection Rule:**
   - Security → Rules → Your Rule → Edit
   - Actions section → Add action
   - Select your webhook connector
   - Run when: "On each rule execution"

---

## 📊 API Endpoints

### GET /
Health check and system info
```json
{
  "status": "online",
  "service": "Security Agent Planner Webhook"
}
```

### POST /webhook/agent/alert
Process new alert through agent workflow
```json
{
  "status": "success",
  "alert_id": "alert-12345",
  "playbook": "Brute Force Attack Response",
  "agents_executed": 4,
  "actions_taken": 5,
  "confidence": 0.85
}
```

### GET /agent/results
Get recent processing results (last 10)
```json
{
  "total_results": 50,
  "showing": 10,
  "results": [...]
}
```

### GET /agent/stats
Get processing statistics
```json
{
  "total_alerts_processed": 50,
  "playbooks_used": {
    "Brute Force Attack Response": 20,
    "Malware Detection Response": 15
  },
  "average_confidence": 0.82,
  "total_actions_taken": 250
}
```

---

## 🎨 Customization

### Add New Playbook:
```python
PLAYBOOKS["custom_attack"] = {
    "name": "Custom Attack Response",
    "severity": ["high", "critical"],
    "indicators": ["custom", "attack", "pattern"],
    "flow": ["triage_agent", "custom_agent", "response_agent"],
    "description": "Handle custom attack type",
    "actions": [
        "Custom action 1",
        "Custom action 2"
    ]
}
```

### Add New Agent:
```python
def custom_agent(state: AgentState) -> AgentState:
    """Custom specialist agent"""
    print("🔧 CUSTOM AGENT - Custom Analysis")
    
    # Your analysis logic here
    result = {
        "agent": "custom",
        "timestamp": datetime.now().isoformat(),
        "findings": "Custom analysis results"
    }
    
    state["analysis_results"]["custom"] = result
    
    # Move to next agent
    flow = state["playbook"]["flow"]
    current_idx = flow.index(state["current_agent"])
    if current_idx < len(flow) - 1:
        state["current_agent"] = flow[current_idx + 1]
    else:
        state["current_agent"] = "complete"
    
    return state

# Add to workflow
workflow.add_node("custom_agent", custom_agent)
```

---

## 🔐 Security Considerations

1. **API Authentication:** Add API key authentication to webhook
2. **Rate Limiting:** Implement rate limiting for alert ingestion
3. **Input Validation:** Validate all incoming alert data
4. **Secure Storage:** Encrypt sensitive data in results
5. **Access Control:** Restrict access to agent results
6. **Audit Logging:** Log all agent decisions and actions

---

## 📈 Performance Tips

1. **Async Processing:** Use async/await for I/O operations
2. **Caching:** Cache playbook matches for similar alerts
3. **Parallel Agents:** Run independent agents in parallel
4. **Result Pagination:** Limit results returned by API
5. **Database:** Use database instead of JSON files for scale

---

## 🐛 Troubleshooting

### Agent not executing?
```python
# Check workflow routing
print(state["current_agent"])
print(state["playbook"]["flow"])
```

### Playbook not matching?
```python
# Lower matching threshold
if score >= 1:  # Instead of 3
    use_playbook
```

### No results saved?
```python
# Check directory permissions
RESULTS_DIR.mkdir(exist_ok=True, mode=0o755)
```

---

## 🚀 Production Deployment

### Use Gunicorn:
```bash
gunicorn -w 4 -b 0.0.0.0:5000 agent_webhook:app
```

### Systemd Service:
```ini
[Unit]
Description=Security Agent Planner Webhook
After=network.target

[Service]
Type=simple
User=security
WorkingDirectory=/opt/agent-planner
ExecStart=/usr/bin/python3 agent_webhook.py
Restart=always

[Install]
WantedBy=multi-user.target
```

### Docker:
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "agent_webhook.py"]
```

---

## 📚 References

- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/)
- [LangChain Documentation](https://python.langchain.com/)
- [Kibana Webhook Connector](https://www.elastic.co/guide/en/kibana/current/webhook-action-type.html)

---

**Built by Sp4c3K** 🔐  
*Security Analyst | Digital Forensics | CTF Player*
