# 🤖 Security Agent Planner System - HƯỚNG DẪN HOÀN CHỈNH

## 📋 Tổng Quan Hệ Thống

### Kiến Trúc Multi-Agent với LangGraph

```
┌─────────────────────────────────────────────────────────────────┐
│                        KIBANA SIEM                              │
│                    (Detection Rules)                            │
└────────────────────────┬────────────────────────────────────────┘
                         │ Alert
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│                   WEBHOOK RECEIVER                              │
│                  (Flask Server :5000)                           │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│                   🎯 PLANNER AGENT                              │
│                (LLM-Powered Decision Maker)                     │
│                                                                 │
│  1. Receive Alert                                               │
│  2. Analyze with LLM (GPT-4)                                   │
│  3. Match to Playbook                                          │
│  4. Orchestrate Agent Flow                                     │
└────────────────────────┬────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ↓                ↓                ↓
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Playbook   │  │   Playbook   │  │   Playbook   │
│  Brute Force │  │   Malware    │  │  Web Attack  │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │
       ↓                 ↓                 ↓
┌──────────────────────────────────────────────────┐
│         🔄 SPECIALIST AGENT CHAIN                │
├──────────────────────────────────────────────────┤
│                                                  │
│  Step 1: 🔍 TRIAGE AGENT                        │
│    ├─ Assess severity                           │
│    ├─ Determine impact                          │
│    └─ Prioritize response                       │
│                                                  │
│  Step 2: 🌐 NETWORK AGENT                       │
│    ├─ Analyze IPs                               │
│    ├─ Check threat intel                        │
│    └─ Recommend firewall rules                  │
│                                                  │
│  Step 3: 🔬 FORENSIC AGENT (LLM-Enhanced)       │
│    ├─ Collect evidence                          │
│    ├─ Extract IOCs                              │
│    ├─ Build timeline                            │
│    └─ LLM deep analysis                         │
│                                                  │
│  Step 4: 🦠 MALWARE AGENT                       │
│    ├─ Identify malware family                   │
│    ├─ Analyze behavior                          │
│    └─ Recommend mitigation                      │
│                                                  │
│  Step 5: 🌐 WEB APP AGENT                       │
│    ├─ Classify attack type                      │
│    ├─ Find vulnerable endpoint                  │
│    └─ Update WAF rules                          │
│                                                  │
│  Step 6: 📧 EMAIL AGENT                         │
│    ├─ Analyze sender                            │
│    ├─ Scan attachments                          │
│    └─ Quarantine threats                        │
│                                                  │
│  Step 7: 🚨 RESPONSE AGENT                      │
│    ├─ Execute remediation                       │
│    ├─ Block threats                             │
│    ├─ Update defenses                           │
│    └─ Generate report                           │
│                                                  │
└──────────────────┬───────────────────────────────┘
                   │
                   ↓
┌──────────────────────────────────────────────────┐
│            📊 RESULTS & ACTIONS                  │
│                                                  │
│  • Analysis from all agents                      │
│  • Automated remediation actions                 │
│  • Confidence scores                             │
│  • Final incident report                         │
│  • JSON results saved                            │
└──────────────────────────────────────────────────┘
```

---

## 🎯 Cách Hoạt Động Chi Tiết

### 1. Alert Reception & Planner Decision

```python
# STEP 1: Kibana sends alert to webhook
POST http://10.8.0.8:5000/webhook/agent/alert
{
  "id": "alert-12345",
  "rule": {"name": "Brute Force Attack"},
  "kibana.alert.severity": "high",
  "source": {"ip": "203.0.113.45"}
}

# STEP 2: Planner receives alert
🎯 PLANNER AGENT analyzing...

# STEP 3: LLM Analysis (if API key available)
🧠 Consulting GPT-4...
    ↓
GPT-4 analyzes: "This is a brute force authentication attack"
Recommends: "brute_force_attack" playbook
Confidence: 0.92

# STEP 4: Playbook Selection
✅ Matched Playbook: "Brute Force Attack Response"
🔄 Workflow: triage → network → forensic → response
```

### 2. Agent Chain Execution

```python
# Each agent runs in sequence based on playbook flow

Flow: ["triage_agent", "network_agent", "forensic_agent", "response_agent"]

# Agent 1: Triage
🔍 TRIAGE AGENT
├─ Priority: HIGH
├─ Immediate Action: YES
└─ Impact: Medium to High

# Agent 2: Network
🌐 NETWORK AGENT
├─ Source IP: 203.0.113.45
├─ Threat Intel: Known malicious
└─ Action: Block at firewall

# Agent 3: Forensic (with LLM)
🔬 FORENSIC AGENT
├─ Evidence: Auth logs, network pcap
├─ IOCs: 50 failed logins from same IP
├─ Timeline: Attack started 10:30, detected 10:35
└─ LLM Analysis: "Credential stuffing attack using stolen database"

# Agent 4: Response
🚨 RESPONSE AGENT
├─ ✅ Block source IP
├─ ✅ Enforce MFA on affected accounts
├─ ✅ Reset compromised passwords
└─ ✅ Alert SOC team
```

### 3. State Management

```python
# State flows through all agents
AgentState = {
    "alert": {original_alert_data},
    "playbook": {
        "id": "brute_force_attack",
        "name": "Brute Force Attack Response",
        "flow": ["triage", "network", "forensic", "response"]
    },
    "current_agent": "network_agent",  # Currently executing
    "analysis_results": {
        "triage": {...},
        "network": {...}
    },
    "actions_taken": [],
    "confidence": 0.92
}
```

---

## 🚀 Cài Đặt & Sử Dụng

### Step 1: Install Dependencies
```powershell
cd C:\Users\Public\github-portfolio\agent-system
pip install -r requirements.txt
```

### Step 2: Configure Environment (Optional - for LLM features)
```powershell
# Nếu muốn dùng GPT-4 cho intelligent analysis
$env:OPENAI_API_KEY = "sk-your-api-key-here"
```

### Step 3: Start Server
```powershell
# Basic version (rule-based only)
python agent_webhook.py

# LLM-enhanced version (requires API key)
python agent_planner_llm.py
```

### Step 4: Test System
```powershell
# Test single alert type
python test_agent.py brute_force

# Test all scenarios
python test_agent.py
```

---

## 🧪 Test Cases Available

```python
TEST_ALERTS = {
    "brute_force": "Multiple failed login attempts",
    "malware": "Ransomware activity detected",
    "data_exfiltration": "Large data transfer to external IP",
    "web_attack": "SQL injection attempt",
    "phishing": "Suspicious email with credential harvesting",
    "privilege_escalation": "Unauthorized admin access attempt"
}
```

### Test Example:
```powershell
# Test brute force scenario
python test_agent.py brute_force

# Output:
🎯 PLANNER AGENT - Analyzing Alert
📚 Playbook Matched: Brute Force Attack Response
🔄 Workflow: triage_agent → network_agent → forensic_agent → response_agent

🔍 TRIAGE AGENT - Initial Assessment
✅ Priority: high
⚡ Immediate Action Required: True

🌐 NETWORK AGENT - Network Analysis  
🔴 Source IP: 203.0.113.45
⚠️  Threat Level: Known malicious
🛡️  Action: Block IP at firewall level

🔬 FORENSIC AGENT - Deep Analysis
📦 Evidence Collected: 4 items
🔍 IOCs Found: 3
✨ Confidence: 85%

🚨 RESPONSE AGENT - Automated Remediation
⚡ Executing: Block source IP
⚡ Executing: Enforce MFA
⚡ Executing: Reset compromised passwords
⚡ Executing: Alert SOC team
✅ Total Actions Executed: 4
🎉 Incident Response Complete!
```

---

## 📚 Playbooks Chi Tiết

### Playbook 1: Brute Force Attack
```yaml
Trigger Keywords:
  - "failed login", "authentication failure"
  - "password", "brute force"

Severity: HIGH, CRITICAL

Agent Flow:
  1. Triage → Assess severity
  2. Network → Check source IP reputation
  3. Forensic → Collect auth logs
  4. Response → Block IP + enforce MFA

Actions:
  ✓ Block source IP address
  ✓ Enforce MFA on affected accounts
  ✓ Reset compromised passwords
  ✓ Alert SOC team
```

### Playbook 2: Malware Detection
```yaml
Trigger Keywords:
  - "malware", "virus", "trojan"
  - "ransomware", "suspicious file"

Severity: CRITICAL, HIGH

Agent Flow:
  1. Triage → Assess impact
  2. Forensic → Collect system artifacts
  3. Malware → Analyze malware family
  4. Response → Isolate host + deploy EDR

Actions:
  ✓ Isolate infected host
  ✓ Collect IOCs (file hashes, registry keys)
  ✓ Analyze malware sample
  ✓ Deploy EDR response
```

### Playbook 3: Web Attack
```yaml
Trigger Keywords:
  - "sql injection", "xss", "web attack"
  - "path traversal", "command injection"

Severity: MEDIUM, HIGH, CRITICAL

Agent Flow:
  1. Triage → Initial assessment
  2. Network → Analyze request patterns
  3. WebApp → Identify vulnerable endpoint
  4. Response → Update WAF + patch

Actions:
  ✓ Block malicious requests
  ✓ Update WAF rules
  ✓ Patch vulnerable endpoint
  ✓ Enable additional logging
```

---

## 🧠 LLM Integration (Optional)

### Với OpenAI API Key:
```python
# Planner sử dụng GPT-4 để:
1. Phân tích alert intelligence
2. Recommend playbook phù hợp nhất
3. Đánh giá confidence score
4. Giải thích reasoning

# Forensic Agent sử dụng LLM để:
1. Deep analysis của attack patterns
2. Timeline reconstruction
3. IOC extraction từ unstructured data
4. Threat attribution
```

### Không có API Key:
```python
# System fallback về rule-based matching
- Keyword matching
- Severity-based routing
- Predetermined workflows
- Still fully functional!
```

---

## 📊 API Endpoints

### GET /
Health check
```json
{
  "status": "online",
  "service": "Security Agent Planner"
}
```

### POST /webhook/agent/alert
Main endpoint cho Kibana alerts
```json
Request:
{
  "id": "alert-123",
  "rule": {"name": "Attack Detected"},
  "kibana.alert.severity": "high"
}

Response:
{
  "status": "success",
  "playbook": "Brute Force Attack Response",
  "agents_executed": 4,
  "actions_taken": 5,
  "confidence": 0.92
}
```

### GET /agent/results
View recent results (last 10)

### GET /agent/stats
System statistics
```json
{
  "total_alerts_processed": 150,
  "playbooks_used": {
    "Brute Force Attack": 50,
    "Malware Detection": 30
  },
  "average_confidence": 0.85,
  "total_actions_taken": 750
}
```

---

## 🔧 Customize Playbooks

### Thêm Playbook Mới:
```python
# In agent_planner.py, thêm vào PLAYBOOKS dict:

PLAYBOOKS["custom_attack"] = {
    "name": "Custom Attack Response",
    "severity": ["high", "critical"],
    "indicators": ["custom", "keyword", "patterns"],
    "flow": ["triage_agent", "custom_agent", "response_agent"],
    "description": "Handle custom security incident",
    "actions": [
        "Custom remediation step 1",
        "Custom remediation step 2",
        "Custom remediation step 3"
    ]
}
```

### Tạo Custom Agent:
```python
def custom_agent(state: AgentState) -> AgentState:
    """Your custom specialist agent"""
    print("🔧 CUSTOM AGENT - Custom Analysis")
    
    # Your analysis logic
    result = {
        "agent": "custom",
        "findings": "Your findings here"
    }
    
    state["analysis_results"]["custom"] = result
    
    # Route to next agent
    flow = state["playbook"]["flow"]
    current_idx = flow.index(state["current_agent"])
    state["current_agent"] = flow[current_idx + 1] if current_idx < len(flow)-1 else "complete"
    
    return state

# Add to workflow
workflow.add_node("custom_agent", custom_agent)
```

---

## 🎯 Kibana Configuration

### Connector Setup:
```
1. Kibana → Stack Management → Connectors
2. Create Webhook Connector:
   - Name: Security Agent Planner
   - URL: http://10.8.0.8:5000/webhook/agent/alert
   - Method: POST
   - Headers: Content-Type: application/json

3. Body Template:
{
  "id": "{{alert.id}}",
  "rule": {
    "name": "{{rule.name}}",
    "description": "{{rule.description}}"
  },
  "kibana.alert.severity": "{{alert.severity}}",
  "source": {"ip": "{{source.ip}}"},
  "destination": {"ip": "{{destination.ip}}"},
  "timestamp": "{{@timestamp}}"
}
```

---

## 🏆 Lợi Ích Của Hệ Thống

✅ **Automated Response:** Tự động xử lý incidents không cần human intervention  
✅ **Intelligent Routing:** LLM-powered decision making  
✅ **Playbook-Based:** Structured, repeatable workflows  
✅ **Multi-Agent:** Specialized agents for different attack types  
✅ **Scalable:** Easy to add new playbooks and agents  
✅ **Observable:** Full logging and result tracking  
✅ **Flexible:** Works with or without LLM integration  

---

**Built by Sp4c3K** 🔐  
*Security Analyst | Digital Forensics | CTF Player*

🔗 Files:
- `agent_planner.py` - Core multi-agent system
- `agent_planner_llm.py` - LLM-enhanced version  
- `agent_webhook.py` - Flask webhook server
- `test_agent.py` - Test suite
- `config.py` - Configuration
