#!/usr/bin/env python3
"""
Telegram Notification Agent
Author: Sp4c3K
Description: Send security alerts and analysis to Telegram
"""

import os
import json
import logging
import requests
from typing import Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class TelegramNotificationAgent:
    """Agent for sending notifications to Telegram"""
    
    def __init__(
        self,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None
    ):
        """
        Initialize Telegram Notification Agent
        
        Args:
            bot_token: Telegram Bot Token
            chat_id: Telegram Chat ID to send messages to
        """
        self.bot_token = bot_token or os.getenv('TELEGRAM_BOT_TOKEN')
        self.chat_id = chat_id or os.getenv('TELEGRAM_CHAT_ID')
        
        if not self.bot_token:
            logger.warning("⚠️  Telegram Bot Token not configured")
        if not self.chat_id:
            logger.warning("⚠️  Telegram Chat ID not configured")
        
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}"
        
        logger.info("Telegram Notification Agent initialized")
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters for Telegram"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;'))
    
    def send_message(self, text: str, parse_mode: str = "HTML") -> Dict:
        """
        Send a text message to Telegram
        
        Args:
            text: Message text
            parse_mode: Parse mode (HTML or Markdown)
            
        Returns:
            Dict with success status and response
        """
        if not self.bot_token or not self.chat_id:
            return {
                "success": False,
                "error": "Telegram credentials not configured"
            }
        
        try:
            url = f"{self.api_url}/sendMessage"
            payload = {
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": parse_mode,
                "disable_web_page_preview": True
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                logger.info("✅ Message sent to Telegram successfully")
                return {
                    "success": True,
                    "response": response.json()
                }
            else:
                logger.error(f"❌ Failed to send Telegram message: {response.status_code} - {response.text}")
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            logger.error(f"❌ Error sending Telegram message: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def send_alert_notification(self, workflow_result: Dict) -> Dict:
        """
        Send security alert notification with analysis summary
        
        Args:
            workflow_result: Complete workflow result from process_alert()
            
        Returns:
            Dict with success status
        """
        try:
            # Extract key information
            alert_info = workflow_result.get('alert', {})
            playbook = workflow_result.get('playbook', {})
            ti_results = workflow_result.get('threat_intelligence', {})
            siem_results = workflow_result.get('siem_investigation', {})
            analysis = workflow_result.get('forensic_analysis', {})
            actions = workflow_result.get('response_actions', [])
            
            # Build notification message
            message = self._build_alert_message(
                alert_info, 
                playbook, 
                ti_results, 
                siem_results,
                analysis, 
                actions
            )
            
            # Send message
            result = self.send_message(message)
            
            if result.get('success'):
                logger.info("✅ Alert notification sent to Telegram")
            else:
                logger.error(f"❌ Failed to send alert notification: {result.get('error')}")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Error building alert notification: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _build_alert_message(
        self,
        alert_info: Dict,
        playbook: Dict,
        ti_results: Dict,
        siem_results: Dict,
        analysis: Dict,
        actions: list
    ) -> str:
        """
        Build formatted alert message for Telegram
        
        Args:
            alert_info: Alert information
            playbook: Matched playbook
            ti_results: Threat intelligence results
            siem_results: SIEM investigation results
            analysis: Forensic analysis
            actions: Response actions
            
        Returns:
            Formatted message string
        """
        # Header with emoji based on severity
        severity = alert_info.get('severity', 'unknown').lower()
        severity_emoji = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
            'unknown': '⚪'
        }.get(severity, '⚪')
        
        lines = [
            f"{severity_emoji} <b>SECURITY ALERT</b> {severity_emoji}",
            "",
            f"<b>Rule:</b> {self._escape_html(alert_info.get('rule_name', 'Unknown'))}",
            f"<b>Severity:</b> {severity.upper()}",
            f"<b>Time:</b> {self._escape_html(alert_info.get('timestamp', 'Unknown'))}",
            f"<b>Playbook:</b> {self._escape_html(playbook.get('name', 'Unknown'))}",
            ""
        ]
        
        # Threat Intelligence Summary
        ti_ips = ti_results.get('ips', [])
        if ti_ips:
            lines.append("🔍 <b>Threat Intelligence:</b>")
            for ip_info in ti_ips[:3]:  # Max 3 IPs
                ip = ip_info.get('ip', 'Unknown')
                verdict = ip_info.get('verdict', 'unknown').upper()
                verdict_emoji = {
                    'MALICIOUS': '🚫',
                    'SUSPICIOUS': '⚠️',
                    'CLEAN': '✅',
                    'UNKNOWN': '❓'
                }.get(verdict, '❓')
                lines.append(f"  {verdict_emoji} <code>{ip}</code> - {verdict}")
            lines.append("")
        
        # WAF Context (if available)
        waf_enabled = siem_results.get('waf_context_enabled', False)
        if waf_enabled:
            context_queries = siem_results.get('context_queries', [])
            lines.append("🛡️ <b>WAF Context:</b>")
            for ctx in context_queries:
                query_type = ctx.get('query_type', '')
                result = ctx.get('result', {})
                total = result.get('total_hits', 0)
                
                if query_type == 'waf_source_ip_events':
                    lines.append(f"  • Events from attacker: <code>{total}</code>")
                elif query_type == 'waf_blocked_requests':
                    lines.append(f"  • Blocked requests: <code>{total}</code>")
                elif query_type == 'recent_waf_activity':
                    lines.append(f"  • Recent activity: <code>{total}</code>")
            lines.append("")
        
        # Key Findings (short version)
        findings = analysis.get('key_findings', [])
        if findings:
            lines.append("📊 <b>Key Findings:</b>")
            for finding in findings[:3]:  # Max 3 findings
                # Truncate long findings
                short_finding = finding[:120] + "..." if len(finding) > 120 else finding
                lines.append(f"  • {self._escape_html(short_finding)}")
            lines.append("")
        
        # Attack Pattern
        attack_pattern = analysis.get('web_attack_pattern') or analysis.get('attack_pattern', '')
        if attack_pattern and attack_pattern != 'Undetermined':
            # Truncate long pattern description
            short_pattern = attack_pattern[:150] + "..." if len(attack_pattern) > 150 else attack_pattern
            lines.append("⚔️ <b>Attack Pattern:</b>")
            lines.append(f"  {self._escape_html(short_pattern)}")
            lines.append("")
        
        # IOCs
        iocs = analysis.get('iocs', [])
        if iocs:
            lines.append("🎯 <b>IOCs:</b>")
            for ioc in iocs[:5]:  # Max 5 IOCs
                lines.append(f"  • <code>{self._escape_html(ioc)}</code>")
            lines.append("")
        
        # Response Actions (critical only)
        critical_actions = [a for a in actions if 'critical' in a.lower()]
        if critical_actions:
            lines.append("🚨 <b>Critical Actions:</b>")
            for action in critical_actions[:3]:
                # Clean up action text
                action_text = action.replace('[AUTO] ', '').replace('[MANUAL] ', '').split('(')[0].strip()
                lines.append(f"  • {self._escape_html(action_text)}")
            lines.append("")
        
        # Workflow Diagram
        lines.append("")
        lines.append("━━━━━━━━━━━━━━━━━━━━━")
        lines.append("📋 <b>Workflow Executed:</b>")
        lines.append("")
        lines.append("Alert → Planner → TI Check → SIEM → AI Analysis → Response → Notify")
        lines.append("")
        lines.append("✓ Playbook selected")
        lines.append(f"✓ TI checked: {len(ti_ips)} IP(s)")
        
        # Count SIEM events
        context_queries = siem_results.get('context_queries', [])
        total_events = sum(q.get('result', {}).get('total_hits', 0) for q in context_queries)
        lines.append(f"✓ SIEM queried: {total_events} event(s)")
        
        lines.append(f"✓ AI analysis: {len(findings)} finding(s)")
        lines.append(f"✓ Actions planned: {len(critical_actions)} critical")
        
        # Footer
        lines.append("")
        lines.append(f"🕐 Analysis Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        return "\n".join(lines)
    
    def send_test_message(self) -> Dict:
        """
        Send a test message to verify Telegram configuration
        
        Returns:
            Dict with success status
        """
        message = (
            "🔔 *Test Notification*\n\n"
            "Telegram Notification Agent is configured correctly!\n\n"
            f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        
        return self.send_message(message)


# Test function
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Test with sample data
    agent = TelegramNotificationAgent()
    
    # Send test message
    result = agent.send_test_message()
    print(f"\nTest result: {json.dumps(result, indent=2)}")
