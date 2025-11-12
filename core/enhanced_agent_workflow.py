#!/usr/bin/env python3
"""
Enhanced Agent Workflow with Threat Intelligence and SIEM Queries
Author: Sp4c3K
Description: Multi-agent workflow with TI checking and SIEM forensics
"""

import os
import json
import logging
from typing import TypedDict, Annotated, List
import operator
from datetime import datetime
from pathlib import Path

# Load environment variables
try:
    from dotenv import load_dotenv
    # Load from config/.env
    env_path = Path(__file__).parent.parent / 'config' / '.env'
    load_dotenv(dotenv_path=env_path)
    logging.info(f"✅ Loaded environment variables from {env_path}")
except ImportError:
    logging.warning("⚠️  python-dotenv not installed, using system environment variables")
except Exception as e:
    logging.warning(f"⚠️  Could not load .env file: {e}")

# LangGraph imports
from langgraph.graph import StateGraph, END
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langchain_google_genai import ChatGoogleGenerativeAI

# Our modules
from .playbook_loader import PlaybookLoader
from .threat_intelligence_agent import ThreatIntelligenceAgent
from .siem_query_agent import SIEMQueryAgent
from .telegram_notification_agent import TelegramNotificationAgent

logger = logging.getLogger(__name__)

# ============================================================================
# STATE DEFINITION
# ============================================================================

class AgentState(TypedDict):
    """State for the agent workflow"""
    alert: dict
    playbook_id: str
    playbook: dict
    messages: Annotated[List[BaseMessage], operator.add]
    ti_results: dict
    siem_results: dict
    analysis_results: dict
    actions_taken: List[str]
    confidence: float
    ti_checked: bool  # NEW: Track if TI check is done


# ============================================================================
# PLANNER AGENT
# ============================================================================

def planner_agent(state: AgentState) -> AgentState:
    """
    Planner: Match alert to playbook
    """
    logger.info("="*80)
    logger.info("🧠 PLANNER AGENT - Matching Alert to Playbook")
    logger.info("="*80)
    
    alert = state["alert"]
    
    # Load playbooks
    playbook_loader = PlaybookLoader()
    
    # Match playbook
    playbook_id, confidence = playbook_loader.match_playbook(alert)
    playbook = playbook_loader.get_playbook(playbook_id)
    
    if not playbook:
        logger.error(f"❌ Playbook not found: {playbook_id}")
        playbook = {
            "name": "Default Incident Response",
            "workflow": ["triage_agent", "forensic_agent", "response_agent"],
            "threat_intelligence": {"check_ip": False}
        }
    
    logger.info(f"✅ Selected Playbook: {playbook['name']}")
    logger.info(f"📊 Confidence: {confidence:.2%}")
    
    state["playbook_id"] = playbook_id
    state["playbook"] = playbook
    state["confidence"] = confidence
    state["ti_checked"] = False  # Initialize TI check flag
    
    state["messages"].append(
        AIMessage(content=f"Selected playbook: {playbook['name']} (confidence: {confidence:.2%})")
    )
    
    return state


# ============================================================================
# THREAT INTELLIGENCE AGENT
# ============================================================================

def ti_agent(state: AgentState) -> AgentState:
    """
    Threat Intelligence Agent: Check IOCs against TI sources
    """
    logger.info("="*80)
    logger.info("🔍 THREAT INTELLIGENCE AGENT")
    logger.info("="*80)
    
    alert = state["alert"]
    playbook = state["playbook"]
    
    # Check if TI is enabled in playbook
    ti_config = playbook.get('threat_intelligence', {})
    
    if not ti_config.get('check_ip') and not ti_config.get('check_domain') and not ti_config.get('check_hash'):
        logger.info("⚠️  TI check disabled in playbook, skipping...")
        state["ti_checked"] = True
        state["ti_results"] = {"enabled": False, "message": "TI check disabled in playbook"}
        return state
    
    # Initialize TI agent
    ti_agent = ThreatIntelligenceAgent()
    
    # Analyze IOCs
    ti_results = ti_agent.analyze_iocs(alert)
    
    # Update state
    state["ti_checked"] = True
    state["ti_results"] = ti_results
    
    # Add summary to messages
    verdict = ti_results.get('overall_verdict', 'unknown')
    ips_checked = len(ti_results.get('ips', []))
    
    summary = f"TI Analysis Complete: {ips_checked} IPs checked, Overall verdict: {verdict.upper()}"
    state["messages"].append(AIMessage(content=summary))
    
    logger.info(f"✅ {summary}")
    
    return state


# ============================================================================
# FORENSICS AGENT WITH SIEM QUERIES
# ============================================================================

def forensic_agent(state: AgentState) -> AgentState:
    """
    Forensic Agent: Execute SIEM queries for investigation
    """
    logger.info("="*80)
    logger.info("🔬 FORENSIC AGENT - SIEM Investigation")
    logger.info("="*80)
    
    alert = state["alert"]
    playbook = state["playbook"]
    ti_results = state.get("ti_results", {})
    
    # Initialize SIEM agent
    siem_agent = SIEMQueryAgent(
        kibana_url=os.getenv('KIBANA_URL', 'https://10.8.0.13:5601'),
        username=os.getenv('KIBANA_USERNAME', 'elastic'),
        password=os.getenv('KIBANA_PASSWORD'),
        verify_ssl=False
    )
    
    # Execute playbook queries
    siem_results = siem_agent.execute_playbook_queries(playbook, alert)
    
    # Additional context queries from Data View (only for WAF alerts)
    context_queries = []
    
    # Detect if this is a WAF/ModSecurity alert
    # Check multiple possible field names
    alert_name = alert.get('alert_name', '').lower()
    rule_name = alert.get('rule', {}).get('name', '').lower() if isinstance(alert.get('rule'), dict) else alert.get('rule_name', '').lower()
    alert_desc = alert.get('description', '').lower()
    rule_desc = alert.get('rule', {}).get('description', '').lower() if isinstance(alert.get('rule'), dict) else ''
    log_source = alert.get('log_source', '').lower()
    
    # Combine all text to search
    search_text = f"{alert_name} {rule_name} {alert_desc} {rule_desc} {log_source}"
    
    is_waf_alert = any([
        'modsecurity' in search_text,
        'modsec' in search_text,
        'waf' in search_text,
        'web attack' in search_text,
        'sql injection' in search_text,
        'xss' in search_text,
        'web application attack' in search_text
    ])
    
    if is_waf_alert:
        logger.info("🛡️  WAF Alert detected - querying ModSecurity Data View for context")
        data_view_id = os.getenv('KIBANA_DATA_VIEW_ID', '31d5c87e-5754-4471-9988-74841088eb7e')
        
        # Extract source IP from various possible fields
        source_ip = None
        # Try direct fields first
        source_ip = alert.get('source_ip') or alert.get('client_ip')
        # Try nested source.ip
        if not source_ip or source_ip == 'unknown':
            source_ip = alert.get('source', {}).get('ip') if isinstance(alert.get('source'), dict) else None
        # Try raw.transaction.client_ip
        if not source_ip or source_ip == 'unknown':
            source_ip = alert.get('raw', {}).get('transaction.client_ip') if isinstance(alert.get('raw'), dict) else None
        # Try threshold_result
        if not source_ip or source_ip == 'unknown':
            threshold_terms = alert.get('raw', {}).get('kibana.alert.threshold_result', {}).get('terms', [])
            for term in threshold_terms:
                if term.get('field') == 'transaction.client_ip':
                    source_ip = term.get('value')
                    break
        
        # Query 1: Get related events from same source IP
        if source_ip:
            logger.info(f"🔍 Querying WAF logs for source IP: {source_ip}")
            ip_events = siem_agent.query_data_view(
                data_view_id=data_view_id,
                query=f"transaction.client_ip:{source_ip}",
                timerange="24h",
                size=30
            )
            context_queries.append({
                "query_type": "waf_source_ip_events",
                "source_ip": source_ip,
                "result": ip_events
            })
            logger.info(f"✅ Found {ip_events.get('total_hits', 0)} WAF events from source IP")
        
        # Query 2: Get blocked/denied requests (HTTP 403, 502, etc.)
        logger.info("🔍 Querying WAF logs for blocked requests")
        blocked_events = siem_agent.query_data_view(
            data_view_id=data_view_id,
            query="transaction.response.http_code:(403 OR 502 OR 500)",
            timerange="1h",
            size=20
        )
        context_queries.append({
            "query_type": "waf_blocked_requests",
            "result": blocked_events
        })
        logger.info(f"✅ Found {blocked_events.get('total_hits', 0)} blocked requests")
        
        # Query 3: Get recent WAF events for attack pattern analysis
        logger.info("🔍 Querying WAF logs for recent activity (15min)")
        recent_waf_events = siem_agent.query_data_view(
            data_view_id=data_view_id,
            query="log_type:modsec",
            timerange="15m",
            size=50
        )
        context_queries.append({
            "query_type": "recent_waf_activity",
            "result": recent_waf_events
        })
        logger.info(f"✅ Found {recent_waf_events.get('total_hits', 0)} recent WAF events")
        
        # Add context queries to siem_results
        siem_results["context_queries"] = context_queries
        siem_results["waf_context_enabled"] = True
    else:
        logger.info("ℹ️  Non-WAF alert - skipping Data View context queries")
        siem_results["context_queries"] = []
        siem_results["waf_context_enabled"] = False
    
    # Update state
    state["siem_results"] = siem_results
    
    # Analyze findings with Gemini (if available)
    api_key = os.getenv("GOOGLE_API_KEY")
    if api_key:
        llm = ChatGoogleGenerativeAI(
            google_api_key=api_key,
            model="gemini-2.5-flash",
            temperature=0.0,
            convert_system_message_to_human=True
        )
        
        # Build forensic analysis prompt
        waf_enabled = siem_results.get('waf_context_enabled', False)
        
        if waf_enabled and context_queries:
            # WAF alert with context
            context_summary = []
            for ctx_query in context_queries:
                query_type = ctx_query.get('query_type', 'unknown')
                result = ctx_query.get('result', {})
                total_hits = result.get('total_hits', 0)
                context_summary.append(f"- {query_type}: {total_hits} events found")
            
            prompt = f"""You are a WAF/Web security forensics expert analyzing ModSecurity alerts.

Alert: {json.dumps(alert, indent=2)}

Threat Intelligence Results: {json.dumps(ti_results, indent=2)}

SIEM Playbook Query Results: {json.dumps(siem_results.get('queries', []), indent=2)}

WAF Context Queries:
{chr(10).join(context_summary)}

WAF Event Details: {json.dumps(context_queries, indent=2)[:5000]}

Analyze the web attack pattern and provide forensic analysis in JSON format:
{{
    "key_findings": ["finding1", "finding2", ...],
    "attack_timeline": ["event1 with timestamp", "event2 with timestamp", ...],
    "web_attack_pattern": "type of web attack (SQL injection, XSS, etc.) and techniques observed",
    "attacker_behavior": "analysis of attacker's actions and intent",
    "iocs": ["attacker IP", "malicious payloads", "suspicious URIs", ...],
    "correlation_analysis": "how WAF events are correlated",
    "recommended_actions": ["action1", "action2", ...]
}}
"""
        else:
            # Non-WAF alert (standard analysis)
            prompt = f"""You are a digital forensics expert analyzing security incident data.

Alert: {json.dumps(alert, indent=2)}

Threat Intelligence Results: {json.dumps(ti_results, indent=2)}

SIEM Playbook Query Results: {json.dumps(siem_results.get('queries', []), indent=2)}

Provide forensic analysis in JSON format:
{{
    "key_findings": ["finding1", "finding2", ...],
    "attack_timeline": ["event1", "event2", ...],
    "iocs": ["ioc1", "ioc2", ...],
    "recommended_actions": ["action1", "action2", ...]
}}
"""
        
        try:
            response = llm.invoke(prompt)
            analysis_text = response.content
            
            # Extract JSON
            if "```json" in analysis_text:
                json_str = analysis_text.split("```json")[1].split("```")[0].strip()
            elif "```" in analysis_text:
                json_str = analysis_text.split("```")[1].split("```")[0].strip()
            else:
                json_str = analysis_text.strip()
            
            analysis = json.loads(json_str)
            state["analysis_results"] = analysis
            
            logger.info("✅ Gemini forensic analysis complete")
            
        except Exception as e:
            logger.warning(f"⚠️  Gemini analysis failed: {str(e)}")
            state["analysis_results"] = {
                "key_findings": ["Manual analysis required"],
                "error": str(e)
            }
    else:
        state["analysis_results"] = {
            "key_findings": ["TI and SIEM data collected"],
            "note": "Gemini API not configured for deep analysis"
        }
    
    # Add to messages
    queries_count = len(siem_results.get('queries', []))
    total_hits = sum(q.get('total_hits', 0) for q in siem_results.get('queries', []))
    
    summary = f"Forensic investigation: {queries_count} SIEM queries executed, {total_hits} total events found"
    state["messages"].append(AIMessage(content=summary))
    
    logger.info(f"✅ {summary}")
    
    return state


# ============================================================================
# RESPONSE AGENT
# ============================================================================

def response_agent(state: AgentState) -> AgentState:
    """
    Response Agent: Execute response actions
    """
    logger.info("="*80)
    logger.info("🚨 RESPONSE AGENT - Taking Actions")
    logger.info("="*80)
    
    playbook = state["playbook"]
    ti_results = state.get("ti_results", {})
    
    actions = []
    
    # Get actions from playbook
    playbook_actions = playbook.get('actions', [])
    
    for action_def in playbook_actions:
        action_name = action_def.get('action', 'Unknown action')
        priority = action_def.get('priority', 'medium')
        automated = action_def.get('automated', False)
        
        if automated:
            actions.append(f"[AUTO] {action_name} (Priority: {priority})")
            logger.info(f"✅ [AUTO] {action_name}")
        else:
            actions.append(f"[MANUAL] {action_name} (Priority: {priority})")
            logger.info(f"📋 [MANUAL] {action_name}")
    
    # Add TI-based actions
    if ti_results.get('overall_verdict') in ['malicious', 'suspicious']:
        actions.append("[AUTO] Block malicious IPs at firewall (Priority: critical)")
        logger.info("✅ [AUTO] Block malicious IPs based on TI verdict")
    
    state["actions_taken"] = actions
    
    summary = f"Response actions planned: {len(actions)} actions"
    state["messages"].append(AIMessage(content=summary))
    
    logger.info(f"✅ {summary}")
    
    return state


# ============================================================================
# NOTIFICATION AGENT
# ============================================================================

def notification_agent(state: AgentState) -> AgentState:
    """
    Notification Agent: Send alert to Telegram
    """
    logger.info("="*80)
    logger.info("📱 NOTIFICATION AGENT - Sending to Telegram")
    logger.info("="*80)
    
    # Check if Telegram is enabled
    telegram_enabled = os.getenv('TELEGRAM_ENABLED', 'false').lower() == 'true'
    
    if not telegram_enabled:
        logger.info("ℹ️  Telegram notifications disabled")
        state["notification_sent"] = False
        return state
    
    # Initialize Telegram agent
    telegram_agent = TelegramNotificationAgent()
    
    # Build workflow result for notification
    workflow_result = {
        "timestamp": datetime.utcnow().isoformat(),
        "alert": {
            "id": state["alert"].get("id", "unknown"),
            "rule_name": state["alert"].get("rule", {}).get("name") if isinstance(state["alert"].get("rule"), dict) else state["alert"].get("rule_name", "Unknown"),
            "severity": state["alert"].get("kibana.alert.severity") or state["alert"].get("severity", "unknown"),
            "timestamp": state["alert"].get("timestamp", "unknown")
        },
        "playbook": {
            "id": state["playbook"].get("id", "unknown"),
            "name": state["playbook"].get("name", "Unknown"),
            "confidence": state["playbook"].get("confidence", 0)
        },
        "threat_intelligence": state.get("ti_results", {}),
        "siem_investigation": state.get("siem_results", {}),
        "forensic_analysis": state.get("analysis_results", {}),
        "response_actions": state.get("actions_taken", [])
    }
    
    # Send notification
    result = telegram_agent.send_alert_notification(workflow_result)
    
    if result.get('success'):
        logger.info("✅ Telegram notification sent successfully")
        state["notification_sent"] = True
    else:
        logger.warning(f"⚠️  Failed to send Telegram notification: {result.get('error')}")
        state["notification_sent"] = False
    
    state["notification_result"] = result
    
    return state


# ============================================================================
# ROUTER FUNCTION
# ============================================================================

def router(state: AgentState) -> str:
    """
    Route to next agent based on state
    """
    playbook = state.get("playbook", {})
    workflow = playbook.get('workflow', [])
    ti_checked = state.get('ti_checked', False)
    ti_config = playbook.get('threat_intelligence', {})
    
    # Check if TI is needed and not yet done
    ti_needed = (ti_config.get('check_ip') or 
                 ti_config.get('check_domain') or 
                 ti_config.get('check_hash'))
    
    if ti_needed and not ti_checked:
        logger.info("🔀 Routing to: ti_agent")
        return "ti_agent"
    
    # Check if forensics is in workflow and TI is done
    if "forensic_agent" in workflow and ti_checked:
        # Check if siem_results already exists
        if not state.get("siem_results"):
            logger.info("🔀 Routing to: forensic_agent")
            return "forensic_agent"
    
    # Go to response if not done yet
    if not state.get("actions_taken"):
        logger.info("🔀 Routing to: response_agent")
        return "response_agent"
    
    # Go to notification if not done yet
    if state.get("notification_sent") is None:
        logger.info("🔀 Routing to: notification_agent")
        return "notification_agent"
    
    # End workflow
    logger.info("🔀 Routing to: END")
    return "end"


# ============================================================================
# WORKFLOW BUILDER
# ============================================================================

def create_enhanced_workflow():
    """Create the enhanced agent workflow with TI and SIEM"""
    
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("planner", planner_agent)
    workflow.add_node("ti_agent", ti_agent)
    workflow.add_node("forensic_agent", forensic_agent)
    workflow.add_node("response_agent", response_agent)
    workflow.add_node("notification_agent", notification_agent)
    
    # Set entry point
    workflow.set_entry_point("planner")
    
    # Add conditional edges
    workflow.add_conditional_edges(
        "planner",
        router,
        {
            "ti_agent": "ti_agent",
            "forensic_agent": "forensic_agent",
            "response_agent": "response_agent",
            "notification_agent": "notification_agent",
            "end": END
        }
    )
    
    workflow.add_conditional_edges(
        "ti_agent",
        router,
        {
            "forensic_agent": "forensic_agent",
            "response_agent": "response_agent",
            "end": END
        }
    )
    
    workflow.add_conditional_edges(
        "forensic_agent",
        router,
        {
            "response_agent": "response_agent",
            "notification_agent": "notification_agent",
            "end": END
        }
    )
    
    workflow.add_conditional_edges(
        "response_agent",
        router,
        {
            "notification_agent": "notification_agent",
            "end": END
        }
    )
    
    workflow.add_edge("notification_agent", END)
    
    return workflow.compile()


# ============================================================================
# HELPER FUNCTION
# ============================================================================

def process_alert(alert: dict) -> dict:
    """
    Process alert through enhanced workflow
    
    Args:
        alert: Alert dictionary
        
    Returns:
        Complete results in JSON format
    """
    # Create workflow
    app = create_enhanced_workflow()
    
    # Initial state
    initial_state = AgentState(
        alert=alert,
        playbook_id="",
        playbook={},
        messages=[],
        ti_results={},
        siem_results={},
        analysis_results={},
        actions_taken=[],
        confidence=0.0,
        ti_checked=False
    )
    
    # Execute workflow
    logger.info("\n" + "="*80)
    logger.info("🚀 STARTING ENHANCED AGENT WORKFLOW")
    logger.info("="*80)
    
    result = app.invoke(initial_state)
    
    # Build JSON output
    output = {
        "timestamp": datetime.utcnow().isoformat(),
        "alert": {
            "id": alert.get('id'),
            "rule_name": alert.get('rule', {}).get('name'),
            "severity": alert.get('kibana.alert.severity'),
            "timestamp": alert.get('timestamp')
        },
        "playbook": {
            "id": result.get('playbook_id'),
            "name": result.get('playbook', {}).get('name'),
            "confidence": result.get('confidence')
        },
        "threat_intelligence": result.get('ti_results', {}),
        "siem_investigation": result.get('siem_results', {}),
        "forensic_analysis": result.get('analysis_results', {}),
        "response_actions": result.get('actions_taken', []),
        "workflow_messages": [msg.content for msg in result.get('messages', [])]
    }
    
    logger.info("\n" + "="*80)
    logger.info("✅ WORKFLOW COMPLETE")
    logger.info("="*80)
    
    return output


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Test with sample alert
    sample_alert = {
        "id": "test-123",
        "timestamp": datetime.utcnow().isoformat(),
        "kibana.alert.severity": "high",
        "rule": {
            "name": "ModSecurity: HighSeverity Requests",
            "description": "Web attack detected"
        },
        "source": {"ip": "196.251.86.122"},
        "destination": {"ip": "10.0.0.1"},
        "agent": {"name": "webserver-01"}
    }
    
    result = process_alert(sample_alert)
    
    print("\n" + "="*80)
    print("FINAL OUTPUT (JSON):")
    print("="*80)
    print(json.dumps(result, indent=2))
