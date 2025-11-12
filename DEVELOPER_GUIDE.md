# 🔧 Developer Guide - Security Agent System

**Version:** 1.0  
**Last Updated:** November 12, 2025  
**Author:** Sp4c3K

---

## 📋 Table of Contents

1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [File Structure](#file-structure)
4. [Detailed File Documentation](#detailed-file-documentation)
5. [Workflow Deep Dive](#workflow-deep-dive)
6. [Configuration Guide](#configuration-guide)
7. [API Integration](#api-integration)
8. [Development Guide](#development-guide)
9. [Troubleshooting](#troubleshooting)

---

## 🎯 System Overview

### What is this system?

This is an **AI-powered Security Incident Response System** that automatically:
1. Receives security alerts from Kibana SIEM
2. Checks IP reputation via Threat Intelligence APIs
3. Queries SIEM for forensic evidence
4. Uses Google Gemini AI to analyze the incident
5. Generates response recommendations
6. Sends formatted alerts to Telegram

### Key Technologies

- **LangGraph**: Multi-agent workflow orchestration
- **LangChain**: LLM integration framework
- **Google Gemini 2.5**: AI analysis engine
- **Elasticsearch/Kibana**: SIEM data source
- **Telegram Bot API**: Team notifications
- **Python 3.13**: Core language

---

## 🏗️ Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     KIBANA SIEM                              │
│  - ModSecurity WAF Logs                                      │
│  - Security Alerts                                           │
│  - Detection Rules                                           │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTP API (Alert JSON)
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              KIBANA COLLECTOR (Optional)                     │
│  File: kibana_collector.py                                   │
│  - Poll alerts from Kibana API                               │
│  - Filter by time range                                      │
│  - Pass to workflow                                          │
└────────────────────┬────────────────────────────────────────┘
                     │ Alert Dict
                     ▼
┌─────────────────────────────────────────────────────────────┐
│           ENHANCED AGENT WORKFLOW (Core)                     │
│  File: core/enhanced_agent_workflow.py                       │
│                                                              │
│  ┌──────────────────────────────────────────────┐          │
│  │  1. PLANNER AGENT                             │          │
│  │     - Load playbooks from YAML                │          │
│  │     - Match alert to appropriate playbook     │          │
│  │     - Extract IOCs (IPs, URLs, domains)       │          │
│  │     - Detect WAF alerts (ModSecurity)         │          │
│  └───────────────┬──────────────────────────────┘          │
│                  │                                           │
│  ┌───────────────▼──────────────────────────────┐          │
│  │  2. THREAT INTELLIGENCE AGENT                 │          │
│  │     File: core/threat_intelligence_agent.py   │          │
│  │     - Check IPs via AbuseIPDB                 │          │
│  │     - Check IPs via VirusTotal                │          │
│  │     - Determine verdict (MALICIOUS/CLEAN)     │          │
│  └───────────────┬──────────────────────────────┘          │
│                  │                                           │
│  ┌───────────────▼──────────────────────────────┐          │
│  │  3. SIEM FORENSIC AGENT                       │          │
│  │     File: core/siem_query_agent.py            │          │
│  │     - Execute playbook queries                │          │
│  │     - Query WAF context (if applicable)       │          │
│  │     - Collect evidence from Elasticsearch     │          │
│  └───────────────┬──────────────────────────────┘          │
│                  │                                           │
│  ┌───────────────▼──────────────────────────────┐          │
│  │  4. FORENSIC ANALYSIS AGENT (Gemini AI)       │          │
│  │     - Correlate TI + SIEM data                │          │
│  │     - Identify attack patterns                │          │
│  │     - Reconstruct timeline                    │          │
│  │     - Extract IOCs                            │          │
│  │     - Generate recommendations                │          │
│  └───────────────┬──────────────────────────────┘          │
│                  │                                           │
│  ┌───────────────▼──────────────────────────────┐          │
│  │  5. RESPONSE PLANNING AGENT                   │          │
│  │     - Load response actions from playbook     │          │
│  │     - Prioritize by severity                  │          │
│  │     - Tag automation capability               │          │
│  └───────────────┬──────────────────────────────┘          │
│                  │                                           │
│  ┌───────────────▼──────────────────────────────┐          │
│  │  6. TELEGRAM NOTIFICATION AGENT               │          │
│  │     File: core/telegram_notification_agent.py │          │
│  │     - Format alert message (HTML)             │          │
│  │     - Include TI results                      │          │
│  │     - Include WAF context                     │          │
│  │     - Include workflow diagram                │          │
│  │     - Send to Telegram                        │          │
│  └───────────────┬──────────────────────────────┘          │
│                  │                                           │
│                  ▼                                           │
│            workflow_result.json                             │
└─────────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    TELEGRAM CHAT                             │
│  - Security team receives formatted alert                    │
│  - Contains: TI verdict, WAF context, findings, IOCs         │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

```
Alert JSON
    │
    ├─> Planner: Extract IOCs, select playbook
    │       │
    │       ├─> playbook_data (name, queries, actions)
    │       └─> iocs (IPs, URLs, domains)
    │
    ├─> TI Agent: Check IOCs reputation
    │       │
    │       └─> ti_results {ip: verdict, abuseipdb_score, virustotal_score}
    │
    ├─> SIEM Agent: Query Elasticsearch
    │       │
    │       ├─> playbook_queries (generic SIEM fields)
    │       └─> waf_context_queries (ModSecurity specific)
    │               │
    │               └─> events from attacker, blocked requests, recent activity
    │
    ├─> Forensic Agent: AI Analysis (Gemini)
    │       │
    │       └─> analysis_results {findings, timeline, attack_pattern, iocs, recommendations}
    │
    ├─> Response Agent: Load actions
    │       │
    │       └─> actions_taken [list of response steps with priority]
    │
    └─> Notification Agent: Format & Send
            │
            └─> Telegram message (HTML formatted)
```

---

## 📁 File Structure

```
agent-system/
│
├── config/
│   ├── .env                    # Environment variables (credentials)
│   └── .env.example            # Template for configuration
│
├── core/                       # Core workflow components
│   ├── __init__.py            # Package initialization
│   ├── enhanced_agent_workflow.py  # Main workflow orchestrator ⭐
│   ├── playbook_loader.py     # YAML playbook loader
│   ├── siem_query_agent.py    # Elasticsearch/Kibana queries
│   ├── telegram_notification_agent.py  # Telegram integration
│   └── threat_intelligence_agent.py   # TI API integration
│
├── playbooks/                  # Response playbooks (YAML)
│   ├── web_attack.yml         # Web application attack response
│   ├── brute_force.yml        # Brute force attack response
│   ├── malware.yml            # Malware infection response
│   └── data_exfiltration.yml  # Data exfiltration response
│
├── tests/                      # Test scripts
│   ├── test_single_alert.py   # Test with sample alert ⭐
│   └── test_dataview_query.py # Test Kibana Data View queries
│
├── config.py                   # Legacy configuration file
├── kibana_collector.py         # Poll alerts from Kibana API ⭐
├── WORKFLOW_DIAGRAM.md         # Workflow visualization
├── DEVELOPER_GUIDE.md          # This file
└── requirements.txt            # Python dependencies
```

---

## 📚 Detailed File Documentation

### 1. `core/enhanced_agent_workflow.py` ⭐ MAIN FILE

**Purpose:** Orchestrates the entire multi-agent workflow using LangGraph.

**Key Components:**

#### State Management
```python
class AgentState(TypedDict):
    """Workflow state shared between all agents"""
    alert: Dict              # Original Kibana alert
    playbook: Dict           # Selected playbook
    iocs: List[str]          # Extracted IOCs
    ti_results: Dict         # Threat intelligence results
    siem_results: Dict       # SIEM query results
    analysis_results: Dict   # AI analysis output
    actions_taken: List[str] # Response actions
    workflow_messages: List[str]  # Progress logs
    
    # State flags (control workflow routing)
    playbook_selected: bool
    ti_checked: bool
    siem_investigated: bool
    analysis_completed: bool
    actions_planned: bool
    notification_sent: bool
```

#### Agent Functions

**1. planner_agent(state: AgentState) -> AgentState**
- **Input:** Raw alert from Kibana
- **Process:**
  - Load all playbooks from `playbooks/` directory
  - Extract IOCs (IPs, URLs, domains) using regex
  - Match alert to best playbook based on keywords
  - Detect if alert is from ModSecurity WAF
- **Output:** 
  - `playbook`: Selected playbook dict
  - `iocs`: List of extracted indicators
  - `playbook_selected`: True
- **Lines:** 63-159

**2. ti_agent(state: AgentState) -> AgentState**
- **Input:** List of IOCs from planner
- **Process:**
  - Initialize ThreatIntelligenceAgent
  - For each IP: call AbuseIPDB and VirusTotal APIs
  - Determine verdict (MALICIOUS if score ≥ 80)
  - Auto-block malicious IPs (if configured)
- **Output:**
  - `ti_results`: Dict with IP verdicts and scores
  - `ti_checked`: True
- **Lines:** 235-288

**3. forensic_agent(state: AgentState) -> AgentState**
- **Input:** 
  - Alert data
  - Selected playbook
  - TI results
- **Process:**
  - Initialize SIEMQueryAgent
  - Execute playbook queries (generic SIEM fields)
  - If WAF alert: Execute 3 additional context queries
    - Query 1: Events from attacker IP (24h, 30 results)
    - Query 2: Blocked requests (HTTP 403/502/500, 1h, 20 results)
    - Query 3: Recent WAF activity (15m, 50 results)
  - Collect all results
- **Output:**
  - `siem_results`: Query results + WAF context
  - `siem_investigated`: True
- **Lines:** 290-335

**4. analysis_agent(state: AgentState) -> AgentState**
- **Input:**
  - Alert
  - Playbook
  - TI results
  - SIEM results
- **Process:**
  - Build comprehensive prompt for Gemini
  - Call Google Gemini 2.5-flash API (temperature=0.0)
  - Parse JSON response
- **Output:**
  - `analysis_results`: JSON with findings, timeline, IOCs, recommendations
  - `analysis_completed`: True
- **Lines:** 337-408

**5. response_agent(state: AgentState) -> AgentState**
- **Input:** Analysis results
- **Process:**
  - Load response actions from playbook
  - Tag each action with priority (critical/high/medium/low)
  - Tag automation capability ([AUTO] vs [MANUAL])
- **Output:**
  - `actions_taken`: List of formatted actions
  - `actions_planned`: True
- **Lines:** 410-432

**6. notification_agent(state: AgentState) -> AgentState**
- **Input:** Complete workflow results
- **Process:**
  - Check if Telegram enabled
  - Build formatted message (HTML)
  - Send via Telegram API
- **Output:**
  - `notification_sent`: True
- **Lines:** 434-494

#### Workflow Routing

**router(state: AgentState) -> str**
- **Purpose:** Determine next agent to execute
- **Logic:**
  ```python
  if playbook_selected is None → "planner"
  elif ti_checked is None → "ti_agent"
  elif siem_investigated is None → "forensic_agent"
  elif analysis_completed is None → "forensic_agent"  # AI analysis
  elif actions_planned is None → "response_agent"
  elif notification_sent is None → "notification_agent"
  else → "end"
  ```
- **Lines:** 520-541

#### Workflow Graph Construction

```python
workflow = StateGraph(AgentState)

# Add nodes
workflow.add_node("planner", planner_agent)
workflow.add_node("ti_agent", ti_agent)
workflow.add_node("forensic_agent", forensic_agent)
workflow.add_node("response_agent", response_agent)
workflow.add_node("notification_agent", notification_agent)

# Set entry point
workflow.set_entry_point("planner")

# Add conditional edges (routing based on state)
workflow.add_conditional_edges("planner", router, ...)
workflow.add_conditional_edges("ti_agent", router, ...)
# ... etc

# Compile
app = workflow.compile()
```

**Lines:** 542-596

#### Main Execution Function

```python
def run_workflow(alert_data: Dict) -> Dict:
    """Execute complete workflow for an alert"""
    initial_state = {
        "alert": alert_data,
        "playbook_selected": None,
        "ti_checked": None,
        # ... all state flags
    }
    
    result = app.invoke(initial_state)
    return result
```

**Lines:** 598-620

---

### 2. `core/threat_intelligence_agent.py`

**Purpose:** Check IP/URL/domain reputation via external TI APIs.

**Class: ThreatIntelligenceAgent**

#### Initialization
```python
def __init__(self, abuseipdb_key=None, virustotal_key=None):
    self.abuseipdb_key = abuseipdb_key or os.getenv('ABUSEIPDB_API_KEY')
    self.virustotal_key = virustotal_key or os.getenv('VIRUSTOTAL_API_KEY')
    self.abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
    self.virustotal_url = "https://www.virustotal.com/api/v3"
```

#### Key Methods

**check_ip_abuseipdb(ip_address: str) -> Dict**
- **API:** AbuseIPDB v2
- **Endpoint:** `GET /check?ipAddress={ip}`
- **Headers:** `Key: {api_key}`
- **Response Fields:**
  - `abuseConfidenceScore`: 0-100 (percentage)
  - `totalReports`: Number of abuse reports
  - `countryCode`: IP origin country
  - `usageType`: ISP, hosting, etc.
- **Verdict Logic:**
  - Score ≥ 80: MALICIOUS
  - Score 50-79: SUSPICIOUS
  - Score < 50: CLEAN
- **Lines:** 47-120

**check_ip_virustotal(ip_address: str) -> Dict**
- **API:** VirusTotal v3
- **Endpoint:** `GET /ip_addresses/{ip}`
- **Headers:** `x-apikey: {api_key}`
- **Response Fields:**
  - `last_analysis_stats.malicious`: Number of vendors flagging as malicious
  - `last_analysis_stats.suspicious`: Suspicious count
  - `last_analysis_stats.harmless`: Clean count
- **Verdict Logic:**
  - Malicious ≥ 5: MALICIOUS
  - Malicious 1-4: SUSPICIOUS
  - Malicious = 0: CLEAN
- **Lines:** 122-198

**check_ips(ip_list: List[str]) -> Dict**
- **Purpose:** Check multiple IPs in parallel
- **Process:**
  1. For each IP: call both AbuseIPDB and VirusTotal
  2. Combine results
  3. Determine overall verdict (worst case)
- **Output Format:**
  ```python
  {
    "ips": [
      {
        "ip": "1.2.3.4",
        "verdict": "malicious",
        "abuseipdb": {...},
        "virustotal": {...}
      }
    ],
    "overall_verdict": "malicious"
  }
  ```
- **Lines:** 200-260

---

### 3. `core/siem_query_agent.py`

**Purpose:** Execute queries against Elasticsearch/Kibana for forensic evidence.

**Class: SIEMQueryAgent**

#### Initialization
```python
def __init__(self, kibana_url, username, password, elasticsearch_url=None):
    self.kibana_url = kibana_url
    self.es_url = elasticsearch_url or kibana_url.replace(':5601', ':9200')
    self.auth = HTTPBasicAuth(username, password)
    self.verify_ssl = False  # For self-signed certs
```

#### Key Methods

**execute_queries(queries: List[Dict], params: Dict) -> List[Dict]**
- **Purpose:** Execute playbook queries with parameter substitution
- **Process:**
  1. For each query: substitute {source_ip}, {destination_ip}, etc.
  2. Execute via Elasticsearch API
  3. Return results with metadata
- **Lines:** 68-130

**_substitute_params(query: str, params: Dict) -> str**
- **Purpose:** Replace placeholders in query with actual values
- **Logic:**
  - Extract source_ip from `alert.raw.transaction.client_ip` (WAF)
  - Or from `alert.raw.threshold_result.terms` (threshold alerts)
  - Or from `alert.source.ip` (generic)
  - Replace all `{source_ip}` in query string
- **Lines:** 242-262

**query_data_view(data_view_id, kql_query, timerange, size, sort) -> Dict**
- **Purpose:** Query Kibana Data View via Elasticsearch directly
- **Process:**
  1. Fetch Data View details from Kibana API
     ```
     GET /api/data_views/data_view/{id}
     ```
  2. Get index pattern (e.g., `filebeat-8.19.4`)
  3. Convert KQL to Elasticsearch Query DSL
  4. Execute search
     ```
     POST /{index}/_search
     {
       "query": {...},
       "size": 30,
       "sort": [{"@timestamp": "desc"}]
     }
     ```
- **Returns:**
  ```python
  {
    "success": True,
    "total_hits": 10,
    "results": [...],  # Parsed _source fields
    "raw_hits": [...]  # Full Elasticsearch response
  }
  ```
- **Lines:** 290-423

---

### 4. `core/telegram_notification_agent.py`

**Purpose:** Send formatted security alerts to Telegram.

**Class: TelegramNotificationAgent**

#### Initialization
```python
def __init__(self, bot_token=None, chat_id=None):
    self.bot_token = bot_token or os.getenv('TELEGRAM_BOT_TOKEN')
    self.chat_id = chat_id or os.getenv('TELEGRAM_CHAT_ID')
    self.api_url = f"https://api.telegram.org/bot{self.bot_token}"
```

#### Key Methods

**send_message(text: str, parse_mode: str = "HTML") -> Dict**
- **API:** Telegram Bot API
- **Endpoint:** `POST /sendMessage`
- **Payload:**
  ```json
  {
    "chat_id": "-5040439554",
    "text": "...",
    "parse_mode": "HTML",
    "disable_web_page_preview": true
  }
  ```
- **Lines:** 52-86

**send_alert_notification(workflow_result: Dict) -> Dict**
- **Purpose:** Main entry point for workflow results
- **Process:**
  1. Extract alert info, TI results, SIEM data, analysis, actions
  2. Call `_build_alert_message()` to format
  3. Send via `send_message()`
- **Lines:** 88-124

**_build_alert_message(...) -> str**
- **Purpose:** Build HTML-formatted message
- **Structure:**
  ```
  🟠 SECURITY ALERT 🟠
  
  Rule: modsecurity
  Severity: HIGH
  Time: 2025-11-11T17:56:45Z
  Playbook: Web Attack Response
  
  🔍 Threat Intelligence:
    🚫 196.251.86.122 - MALICIOUS
    • AbuseIPDB: 100% confidence
    • VirusTotal: 9/95 flagged
  
  🛡️ WAF Context:
    • Events from attacker: 1
    • Blocked requests: 10
    • Recent activity: 0
  
  📊 Key Findings:
    • PHP injection targeting phpinfo
    • 6 previous attacks from same IP
  
  ⚔️ Attack Pattern:
    Information disclosure via phpinfo
  
  🎯 IOCs:
    • IP: 196.251.86.122
    • URL: /_profiler/phpinfo
  
  🚨 Critical Actions:
    • Block IP at firewall
    • Check application logs
  
  ━━━━━━━━━━━━━━━━━━━━━
  📋 Workflow Executed:
  
  Alert → Planner → TI Check → SIEM → AI Analysis → Response → Notify
  
  ✓ Playbook selected
  ✓ TI checked: 1 IP(s)
  ✓ SIEM queried: 11 event(s)
  ✓ AI analysis: 7 finding(s)
  ✓ Actions planned: 3 critical
  
  🕐 Analysis Time: 2025-11-12 06:05:48 UTC
  ```
- **Lines:** 126-283

**_escape_html(text: str) -> str**
- **Purpose:** Escape special HTML characters for Telegram
- **Replacements:**
  - `&` → `&amp;`
  - `<` → `&lt;`
  - `>` → `&gt;`
- **Lines:** 44-50

---

### 5. `core/playbook_loader.py`

**Purpose:** Load and parse YAML playbooks.

**Class: PlaybookLoader**

#### Playbook YAML Structure

```yaml
# playbooks/web_attack.yml
name: "Web Application Attack Response"
description: "Response playbook for web application attacks"
category: "web-attack"
severity: "high"

triggers:
  keywords:
    - "web attack"
    - "sql injection"
    - "xss"
    - "path traversal"
  rule_ids:
    - "web-001"
    - "web-002"

investigation:
  siem_queries:
    - name: "Source IP History"
      index: "logs-*"
      query: "source.ip:{source_ip} AND @timestamp:[now-24h TO now]"
      timerange: "24h"
      description: "Check historical activity from source IP"
    
    - name: "User Agent Analysis"
      index: "logs-*"
      query: "user_agent:* AND source.ip:{source_ip}"
      timerange: "7d"
      description: "Identify user agent patterns"

response:
  actions:
    - action: "Block attacking IP at WAF"
      type: "auto"
      priority: "critical"
      
    - action: "Review WAF logs for attack patterns"
      type: "auto"
      priority: "high"
      
    - action: "Check application logs for successful exploits"
      type: "auto"
      priority: "critical"
      
    - action: "Verify database integrity"
      type: "manual"
      priority: "high"
```

#### Key Methods

**load_all_playbooks() -> Dict**
- **Purpose:** Load all YAML files from `playbooks/` directory
- **Returns:** Dict with playbook name as key
- **Lines:** 30-65

**match_playbook(alert: Dict) -> Dict**
- **Purpose:** Find best matching playbook for alert
- **Matching Logic:**
  1. Check alert rule name against playbook keywords
  2. Check alert rule ID against playbook rule_ids
  3. Calculate confidence score
  4. Return best match
- **Lines:** 67-120

---

### 6. `kibana_collector.py` ⭐

**Purpose:** Poll Kibana for new alerts and process them through workflow.

**Key Functions:**

#### KibanaCollector Class

**poll_alerts(start_time, end_time, max_alerts) -> List[Dict]**
- **API:** Kibana Detection Engine API
- **Endpoint:** `POST /api/detection_engine/signals/search`
- **Query:**
  ```json
  {
    "query": {
      "bool": {
        "filter": [
          {"range": {"@timestamp": {"gte": "now-1h"}}}
        ]
      }
    },
    "size": 100,
    "sort": [{"@timestamp": "desc"}]
  }
  ```
- **Returns:** List of alert dicts
- **Lines:** 150-230

**process_alert_with_agent(alert: Dict) -> Dict**
- **Purpose:** Send alert to enhanced_agent_workflow
- **Process:**
  1. Import workflow
  2. Call `run_workflow(alert)`
  3. Save result to JSON
- **Lines:** 400-450

#### Main Execution

```python
if __name__ == "__main__":
    collector = KibanaCollector(
        kibana_url=os.getenv('KIBANA_URL'),
        username=os.getenv('KIBANA_USERNAME'),
        password=os.getenv('KIBANA_PASSWORD')
    )
    
    # Poll every 60 seconds
    while True:
        alerts = collector.poll_alerts()
        for alert in alerts:
            process_alert_with_agent(alert)
        time.sleep(60)
```

**Lines:** 480-530

---

### 7. `tests/test_single_alert.py` ⭐

**Purpose:** Test workflow with a sample ModSecurity alert.

**Sample Alert Structure:**

```python
sample_alert = {
    "kibana.alert.rule.name": "ModSecurity: HighSeverity Requests",
    "kibana.alert.severity": "high",
    "kibana.alert.original_time": "2025-11-11T17:56:45.350Z",
    "kibana.alert.threshold_result": {
        "terms": [
            {
                "field": "transaction.client_ip",
                "value": "196.251.86.122"
            }
        ]
    },
    "kibana.alert.original_event": {
        "transaction": {
            "client_ip": "196.251.86.122",
            "request": {
                "uri": "/_profiler/phpinfo",
                "method": "GET"
            },
            "response": {
                "http_code": 502
            },
            "messages": [
                {
                    "message": "PHP Injection Attack",
                    "details": {
                        "ruleId": "933150",
                        "severity": "2"
                    }
                }
            ]
        }
    }
}
```

**Execution:**

```python
from core.enhanced_agent_workflow import run_workflow

result = run_workflow(sample_alert)

# Save to workflow_result.json
with open('workflow_result.json', 'w') as f:
    json.dump(result, f, indent=2)
```

**Lines:** 1-120

---

## 🔄 Workflow Deep Dive

### Step-by-Step Execution

#### Step 1: Alert Input

**Entry Point:** `run_workflow(alert_data)`

**State Initialization:**
```python
{
  "alert": {...},              # Full Kibana alert
  "playbook_selected": None,   # Triggers planner_agent
  "ti_checked": None,
  "siem_investigated": None,
  "analysis_completed": None,
  "actions_planned": None,
  "notification_sent": None
}
```

#### Step 2: Planner Agent Execution

**Function:** `planner_agent(state)`

**Process:**
1. Load playbooks
   ```python
   loader = PlaybookLoader('playbooks/')
   playbooks = loader.load_all_playbooks()
   ```

2. Extract IOCs
   ```python
   alert_text = json.dumps(state['alert'])
   
   # IP regex: \b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b
   ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', alert_text)
   
   # URL regex
   urls = re.findall(r'https?://[^\s]+', alert_text)
   ```

3. Match playbook
   ```python
   playbook = loader.match_playbook(state['alert'])
   confidence = playbook['confidence']
   ```

4. Detect WAF alert
   ```python
   rule_name = state['alert'].get('kibana.alert.rule.name', '')
   is_waf = 'modsecurity' in rule_name.lower()
   ```

**Output State:**
```python
{
  ...state,
  "playbook": playbook_data,
  "iocs": ["196.251.86.122"],
  "playbook_selected": True  # Routes to ti_agent next
}
```

#### Step 3: TI Agent Execution

**Function:** `ti_agent(state)`

**Process:**
1. Initialize agent
   ```python
   ti = ThreatIntelligenceAgent()
   ```

2. Check each IP
   ```python
   for ip in state['iocs']:
       # AbuseIPDB
       abuse_result = ti.check_ip_abuseipdb(ip)
       # Returns: {abuseConfidenceScore: 100, ...}
       
       # VirusTotal
       vt_result = ti.check_ip_virustotal(ip)
       # Returns: {malicious: 9, suspicious: 2, ...}
   ```

3. Determine verdict
   ```python
   if abuse_score >= 80 or vt_malicious >= 5:
       verdict = "MALICIOUS"
   elif abuse_score >= 50 or vt_malicious >= 1:
       verdict = "SUSPICIOUS"
   else:
       verdict = "CLEAN"
   ```

**Output State:**
```python
{
  ...state,
  "ti_results": {
    "ips": [
      {
        "ip": "196.251.86.122",
        "verdict": "malicious",
        "abuseipdb": {"abuseConfidenceScore": 100},
        "virustotal": {"malicious": 9}
      }
    ],
    "overall_verdict": "malicious"
  },
  "ti_checked": True  # Routes to forensic_agent next
}
```

#### Step 4: SIEM Forensic Agent Execution

**Function:** `forensic_agent(state)`

**Process:**

1. Initialize SIEM agent
   ```python
   siem = SIEMQueryAgent(
       kibana_url=os.getenv('KIBANA_URL'),
       username=os.getenv('KIBANA_USERNAME'),
       password=os.getenv('KIBANA_PASSWORD')
   )
   ```

2. Execute playbook queries
   ```python
   playbook_queries = state['playbook']['investigation']['siem_queries']
   
   for query in playbook_queries:
       # Substitute {source_ip} with actual IP
       query_str = query['query'].replace('{source_ip}', '196.251.86.122')
       
       # Execute
       result = siem.execute_query(query_str, query['index'])
   ```

3. If WAF alert: Execute context queries
   ```python
   if is_waf_alert:
       # Query 1: Events from attacker IP
       result1 = siem.query_data_view(
           data_view_id=DATA_VIEW_ID,
           kql_query="transaction.client_ip:196.251.86.122",
           timerange="24h",
           size=30
       )
       
       # Query 2: Blocked requests
       result2 = siem.query_data_view(
           kql_query="transaction.response.http_code:(403 OR 502 OR 500)",
           timerange="1h",
           size=20
       )
       
       # Query 3: Recent WAF activity
       result3 = siem.query_data_view(
           kql_query="log_type:modsec",
           timerange="15m",
           size=50
       )
   ```

**Output State:**
```python
{
  ...state,
  "siem_results": {
    "queries": [...],  # Playbook query results (0 hits)
    "context_queries": [
      {
        "query_type": "waf_source_ip_events",
        "result": {"total_hits": 1, "results": [...]}
      },
      {
        "query_type": "waf_blocked_requests",
        "result": {"total_hits": 10, "results": [...]}
      },
      {
        "query_type": "recent_waf_activity",
        "result": {"total_hits": 0, "results": []}
      }
    ],
    "waf_context_enabled": True
  },
  "siem_investigated": True  # Routes to forensic_agent again for AI analysis
}
```

#### Step 5: AI Forensic Analysis

**Function:** Still `forensic_agent(state)` but analysis path

**Process:**

1. Build Gemini prompt
   ```python
   prompt = f"""
   Analyze this security incident:
   
   ALERT DATA:
   {json.dumps(state['alert'], indent=2)}
   
   THREAT INTELLIGENCE:
   {json.dumps(state['ti_results'], indent=2)}
   
   SIEM INVESTIGATION:
   {json.dumps(state['siem_results'], indent=2)}
   
   PLAYBOOK CONTEXT:
   {json.dumps(state['playbook'], indent=2)}
   
   Provide analysis in JSON format:
   {{
     "key_findings": [...],
     "attack_timeline": [...],
     "web_attack_pattern": "...",
     "attacker_behavior": "...",
     "iocs": [...],
     "correlation_analysis": "...",
     "recommended_actions": [...]
   }}
   """
   ```

2. Call Gemini API
   ```python
   import google.generativeai as genai
   
   model = genai.GenerativeModel('gemini-2.5-flash')
   response = model.generate_content(
       prompt,
       generation_config={"temperature": 0.0}
   )
   
   analysis = json.loads(response.text)
   ```

**Output State:**
```python
{
  ...state,
  "analysis_results": {
    "key_findings": [
      "PHP injection targeting /_profiler/phpinfo",
      "IP 196.251.86.122 confirmed MALICIOUS by TI",
      "6 previous blocked requests from same IP"
    ],
    "attack_timeline": [
      "2025-11-11T17:56:10Z: PHP injection attempt",
      "2025-11-11T17:56:45Z: Alert generated"
    ],
    "web_attack_pattern": "Information Disclosure via phpinfo",
    "iocs": ["IP: 196.251.86.122", "URL: /_profiler/phpinfo"],
    "recommended_actions": [...]
  },
  "analysis_completed": True  # Routes to response_agent next
}
```

#### Step 6: Response Planning

**Function:** `response_agent(state)`

**Process:**

1. Load actions from playbook
   ```python
   actions = state['playbook']['response']['actions']
   ```

2. Format actions
   ```python
   formatted = []
   for action in actions:
       priority = action['priority']  # critical, high, medium, low
       action_type = action['type']   # auto, manual
       text = action['action']
       
       formatted_action = f"[{action_type.upper()}] {text} (Priority: {priority})"
       formatted.append(formatted_action)
   ```

**Output State:**
```python
{
  ...state,
  "actions_taken": [
    "[AUTO] Block attacking IP at WAF (Priority: critical)",
    "[AUTO] Review WAF logs for attack patterns (Priority: high)",
    "[AUTO] Check application logs for successful exploits (Priority: critical)",
    "[MANUAL] Verify database integrity (Priority: high)",
    "[MANUAL] Review recent code changes (Priority: medium)"
  ],
  "actions_planned": True  # Routes to notification_agent next
}
```

#### Step 7: Telegram Notification

**Function:** `notification_agent(state)`

**Process:**

1. Check if enabled
   ```python
   enabled = os.getenv('TELEGRAM_ENABLED', 'false').lower() == 'true'
   if not enabled:
       return state
   ```

2. Build workflow result
   ```python
   workflow_result = {
       "timestamp": datetime.utcnow().isoformat(),
       "alert": state['alert'],
       "playbook": state['playbook'],
       "threat_intelligence": state['ti_results'],
       "siem_investigation": state['siem_results'],
       "forensic_analysis": state['analysis_results'],
       "response_actions": state['actions_taken']
   }
   ```

3. Send notification
   ```python
   tg = TelegramNotificationAgent()
   result = tg.send_alert_notification(workflow_result)
   ```

**Output State:**
```python
{
  ...state,
  "notification_sent": True  # Routes to END
}
```

---

## ⚙️ Configuration Guide

### Environment Variables (.env file)

```bash
# Kibana/Elasticsearch
KIBANA_URL=https://10.8.0.13:5601
KIBANA_USERNAME=elastic
KIBANA_PASSWORD=AAA@123aaa!@#
KIBANA_DATA_VIEW_ID=31d5c87e-5754-4471-9988-74841088eb7e

# Google Gemini AI
GOOGLE_API_KEY=AIzaSyCYTDvlfesgLrdH8t1yA1kA0EiwoEZ6nG0

# Telegram Notifications
TELEGRAM_ENABLED=true
TELEGRAM_BOT_TOKEN=7825152790:AAFp4YXkEL4Aa0gSleXeqeRcdDljrpTEtSc
TELEGRAM_CHAT_ID=-5040439554

# Threat Intelligence APIs
ABUSEIPDB_API_KEY=43b08d259e748dcce741241d9630dcb3b8173ef5f9f61eade28ed099e7a38fb41b2768a29709f50c
VIRUSTOTAL_API_KEY=8c2d04626b6e7f841232c1a38ed0782f0146cddf4628e05db3403204e1fced71
```

### Getting API Keys

#### 1. Google Gemini API
- Visit: https://makersuite.google.com/app/apikey
- Click "Create API Key"
- Copy key to `GOOGLE_API_KEY`

#### 2. AbuseIPDB
- Visit: https://www.abuseipdb.com/register
- Sign up for free account
- Go to Account → API
- Copy key to `ABUSEIPDB_API_KEY`
- Free tier: 1,000 requests/day

#### 3. VirusTotal
- Visit: https://www.virustotal.com/gui/join-us
- Sign up for free account
- Go to Profile → API Key
- Copy key to `VIRUSTOTAL_API_KEY`
- Free tier: 500 requests/day

#### 4. Telegram Bot
- Open Telegram, search for **@BotFather**
- Send: `/newbot`
- Follow prompts to create bot
- Copy bot token to `TELEGRAM_BOT_TOKEN`
- To get chat ID:
  1. Send a message to your bot
  2. Visit: `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`
  3. Look for `"chat":{"id":-1234567890}`
  4. Copy ID to `TELEGRAM_CHAT_ID`

---

## 🔌 API Integration

### 1. Kibana Detection Engine API

**Endpoint:** `POST /api/detection_engine/signals/search`

**Authentication:** Basic Auth (username:password)

**Request:**
```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "now-1h",
              "lte": "now"
            }
          }
        }
      ]
    }
  },
  "size": 100,
  "sort": [{"@timestamp": {"order": "desc"}}]
}
```

**Response:**
```json
{
  "took": 5,
  "timed_out": false,
  "hits": {
    "total": {"value": 1},
    "hits": [
      {
        "_source": {
          "kibana.alert.rule.name": "...",
          "kibana.alert.severity": "high",
          "kibana.alert.original_time": "...",
          "kibana.alert.original_event": {...}
        }
      }
    ]
  }
}
```

### 2. Elasticsearch Search API

**Endpoint:** `POST /{index}/_search`

**Authentication:** Basic Auth

**Request:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"transaction.client_ip": "1.2.3.4"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "size": 30,
  "sort": [{"@timestamp": "desc"}]
}
```

**Response:** Standard Elasticsearch response with hits

### 3. AbuseIPDB API

**Endpoint:** `GET https://api.abuseipdb.com/api/v2/check`

**Headers:**
- `Accept: application/json`
- `Key: {api_key}`

**Parameters:**
- `ipAddress`: IP to check
- `maxAgeInDays`: 90 (default)
- `verbose`: (optional)

**Response:**
```json
{
  "data": {
    "ipAddress": "1.2.3.4",
    "abuseConfidenceScore": 100,
    "totalReports": 50,
    "countryCode": "CN",
    "usageType": "Data Center/Web Hosting/Transit",
    "isp": "Example ISP",
    "lastReportedAt": "2025-11-11T12:00:00+00:00"
  }
}
```

### 4. VirusTotal API

**Endpoint:** `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}`

**Headers:**
- `x-apikey: {api_key}`

**Response:**
```json
{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "malicious": 9,
        "suspicious": 2,
        "harmless": 80,
        "undetected": 4
      },
      "reputation": -50,
      "country": "CN"
    }
  }
}
```

### 5. Telegram Bot API

**Endpoint:** `POST https://api.telegram.org/bot{token}/sendMessage`

**Request:**
```json
{
  "chat_id": "-5040439554",
  "text": "<b>Alert</b>: High severity incident",
  "parse_mode": "HTML",
  "disable_web_page_preview": true
}
```

**Response:**
```json
{
  "ok": true,
  "result": {
    "message_id": 123,
    "date": 1699876543
  }
}
```

### 6. Google Gemini API

**Endpoint:** Via `google-generativeai` SDK

**Code:**
```python
import google.generativeai as genai

genai.configure(api_key=GOOGLE_API_KEY)

model = genai.GenerativeModel('gemini-2.5-flash')
response = model.generate_content(
    prompt,
    generation_config={
        "temperature": 0.0,
        "candidate_count": 1
    }
)

result = response.text
```

---

## 💻 Development Guide

### Setup Development Environment

1. **Clone repository**
   ```bash
   cd C:\Users\Public\github-portfolio\agent-system
   ```

2. **Install Python 3.13**
   ```bash
   python --version  # Should be 3.13.x
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**
   ```bash
   copy config\.env.example config\.env
   # Edit config\.env with your credentials
   ```

5. **Test workflow**
   ```bash
   python tests\test_single_alert.py
   ```

### Adding New Playbook

1. **Create YAML file** in `playbooks/`
   ```yaml
   # playbooks/my_new_playbook.yml
   name: "My New Attack Type"
   description: "Response for XYZ attacks"
   category: "network"
   severity: "critical"
   
   triggers:
     keywords:
       - "keyword1"
       - "keyword2"
     rule_ids:
       - "rule-123"
   
   investigation:
     siem_queries:
       - name: "Query Name"
         index: "logs-*"
         query: "field:{source_ip}"
         timerange: "1h"
         description: "What this query finds"
   
   response:
     actions:
       - action: "Action description"
         type: "auto"
         priority: "critical"
   ```

2. **Test playbook matching**
   ```python
   from core.playbook_loader import PlaybookLoader
   
   loader = PlaybookLoader('playbooks/')
   playbook = loader.match_playbook(your_alert)
   print(f"Matched: {playbook['name']}")
   ```

### Adding New Agent

1. **Create agent file** in `core/`
   ```python
   # core/my_new_agent.py
   
   class MyNewAgent:
       def __init__(self):
           pass
       
       def process(self, data):
           # Your logic here
           return result
   ```

2. **Add to workflow** in `enhanced_agent_workflow.py`
   ```python
   from .my_new_agent import MyNewAgent
   
   def my_new_agent_node(state: AgentState) -> AgentState:
       agent = MyNewAgent()
       result = agent.process(state['alert'])
       state['my_result'] = result
       state['my_agent_done'] = True
       return state
   
   # Add to graph
   workflow.add_node("my_agent", my_new_agent_node)
   workflow.add_conditional_edges("previous_agent", router, {...})
   ```

3. **Update router**
   ```python
   def router(state: AgentState) -> str:
       # ... existing logic
       if state.get("my_agent_done") is None:
           return "my_agent"
       # ...
   ```

### Debugging Tips

1. **Enable verbose logging**
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

2. **Print state between agents**
   ```python
   def debug_agent(state: AgentState) -> AgentState:
       print(json.dumps(state, indent=2))
       return state
   
   workflow.add_node("debug", debug_agent)
   ```

3. **Test individual agents**
   ```python
   from core.threat_intelligence_agent import ThreatIntelligenceAgent
   
   ti = ThreatIntelligenceAgent()
   result = ti.check_ip_abuseipdb("1.2.3.4")
   print(result)
   ```

4. **Check Elasticsearch queries**
   ```python
   from core.siem_query_agent import SIEMQueryAgent
   
   siem = SIEMQueryAgent(...)
   result = siem.query_data_view(
       data_view_id="...",
       kql_query="transaction.client_ip:1.2.3.4",
       timerange="1h"
   )
   print(f"Found {result['total_hits']} events")
   ```

### Common Issues

#### 1. SSL Certificate Errors
```python
# In siem_query_agent.py
self.verify_ssl = False  # For self-signed certs
```

#### 2. API Rate Limits
- AbuseIPDB: 1,000/day
- VirusTotal: 500/day
- Solution: Implement caching or upgrade to paid tier

#### 3. Telegram HTML Parse Errors
- Always escape special characters: `&`, `<`, `>`
- Use `_escape_html()` method

#### 4. Gemini API Timeout
- Default timeout: 30s
- Increase if needed:
  ```python
  response = model.generate_content(prompt, request_options={"timeout": 60})
  ```

---

## 🐛 Troubleshooting

### Issue: Workflow not finding playbook

**Symptom:** "No matching playbook found"

**Solution:**
1. Check alert rule name contains playbook keywords
2. Verify YAML files in `playbooks/` directory
3. Test manually:
   ```python
   loader = PlaybookLoader('playbooks/')
   playbooks = loader.load_all_playbooks()
   print(playbooks.keys())
   ```

### Issue: TI checks returning UNKNOWN

**Symptom:** All IPs show verdict "UNKNOWN"

**Solution:**
1. Check API keys in `.env` file
2. Verify API keys are valid:
   ```bash
   curl -H "Key: YOUR_KEY" "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8"
   ```
3. Check rate limits not exceeded

### Issue: SIEM queries return 0 results

**Symptom:** All queries show 0 hits

**Solution:**
1. Check Elasticsearch connectivity:
   ```bash
   curl -k -u elastic:password https://10.8.0.13:9200/_cluster/health
   ```
2. Verify index pattern exists:
   ```bash
   curl -k -u elastic:password https://10.8.0.13:9200/_cat/indices
   ```
3. Check time range (default: 24h)
4. For WAF: Ensure data view ID is correct

### Issue: Telegram not sending

**Symptom:** "Telegram notification disabled"

**Solution:**
1. Check `TELEGRAM_ENABLED=true` in `.env`
2. Verify bot token:
   ```bash
   curl https://api.telegram.org/bot<TOKEN>/getMe
   ```
3. Test chat ID:
   ```bash
   curl -X POST "https://api.telegram.org/bot<TOKEN>/sendMessage" \
     -d "chat_id=<CHAT_ID>&text=Test"
   ```

### Issue: Gemini API errors

**Symptom:** "Failed to analyze with Gemini"

**Solution:**
1. Check API key valid
2. Verify quota not exceeded
3. Check prompt size (max: 30k tokens)
4. Try with smaller alert

---

## 📊 Performance Optimization

### Workflow Execution Time

**Typical workflow:** 15-20 seconds

**Breakdown:**
- Planner: 0.5s
- TI checks: 3-5s (parallel)
- SIEM queries: 2-4s
- AI analysis: 5-8s (Gemini)
- Response planning: 0.5s
- Telegram: 1-2s

**Optimization tips:**
1. Cache TI results (1 hour TTL)
2. Limit SIEM query size
3. Use Gemini Flash model (faster than Pro)
4. Parallel execution where possible

### Memory Usage

**Typical:** 150-300 MB

**Spikes during:**
- SIEM large result sets
- Gemini long prompts

**Mitigation:**
- Limit query results to 50 events
- Truncate alert data before sending to Gemini

---

## 🔐 Security Considerations

### Credentials Storage
- **Never commit `.env` to git**
- Use environment variables in production
- Rotate API keys regularly

### API Security
- All external APIs use HTTPS
- Elasticsearch: Basic Auth + TLS
- Telegram: Bot token authentication
- TI APIs: API key authentication

### Data Privacy
- Alert data may contain sensitive info
- Telegram messages are encrypted in transit
- Consider data retention policies

---

## 📚 Additional Resources

### Documentation
- LangGraph: https://python.langchain.com/docs/langgraph
- Google Gemini: https://ai.google.dev/docs
- Elasticsearch: https://www.elastic.co/guide/
- Telegram Bot API: https://core.telegram.org/bots/api

### Related Files
- `WORKFLOW_DIAGRAM.md`: Visual workflow diagram
- `requirements.txt`: Python dependencies
- `config/.env.example`: Configuration template

---

## 🚀 Next Steps

### For New Developers

1. **Read this guide completely**
2. **Run test workflow:** `python tests\test_single_alert.py`
3. **Understand state flow:** Check `AgentState` in each agent
4. **Explore playbooks:** Read YAML files in `playbooks/`
5. **Test each agent:** Run individual agent tests
6. **Modify and test:** Add your own playbook or agent

### For System Integration

1. **Deploy collector:** `python kibana_collector.py --process`
2. **Configure webhook:** Use Flask webhook (if needed)
3. **Set up monitoring:** Track workflow execution times
4. **Implement alerting:** Monitor for workflow failures

### For Advanced Development

1. **Add ML-based playbook matching**
2. **Implement action execution (auto-block, etc.)**
3. **Add more TI sources (IBM X-Force, AlienVault, etc.)**
4. **Create custom SIEM queries per alert type**
5. **Build dashboard for workflow results**

---

**Questions?** Check the code comments or create an issue in the repository.

**Happy coding! 🎉**

