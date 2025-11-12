#!/usr/bin/env python3
"""
Kibana Alert Collector
Author: Sp4c3K
Description: Poll alerts from Kibana SIEM and process through Agent Planner
"""

import requests
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
import logging
from typing import List, Dict
import os
from requests.auth import HTTPBasicAuth

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('kibana_collector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class KibanaAlertCollector:
    """Collector to poll alerts from Kibana"""
    
    def __init__(
        self,
        kibana_url: str,
        username: str = None,
        password: str = None,
        api_key: str = None,
        space_id: str = "default",
        poll_interval: int = 60,
        verify_ssl: bool = True
    ):
        """
        Initialize Kibana Alert Collector
        
        Args:
            kibana_url: Kibana base URL (e.g., http://localhost:5601)
            username: Kibana username (if using basic auth)
            password: Kibana password (if using basic auth)
            api_key: Kibana API key (if using API key auth)
            space_id: Kibana space ID (default: "default")
            poll_interval: Polling interval in seconds (default: 60)
            verify_ssl: Verify SSL certificates (default: True)
        """
        self.kibana_url = kibana_url.rstrip('/')
        self.space_id = space_id
        self.poll_interval = poll_interval
        self.verify_ssl = verify_ssl
        
        # Disable SSL warnings if verify is False
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Setup authentication
        self.auth = None
        self.headers = {
            'kbn-xsrf': 'true',
            'Content-Type': 'application/json'
        }
        
        if api_key:
            self.headers['Authorization'] = f'ApiKey {api_key}'
            logger.info("Using API Key authentication")
        elif username and password:
            self.auth = HTTPBasicAuth(username, password)
            logger.info("Using Basic authentication")
        else:
            logger.warning("No authentication provided - may fail on protected Kibana")
        
        # Base API endpoint
        self.api_base = f"{self.kibana_url}/s/{self.space_id}/api"
        
        # Track processed alerts
        self.processed_alerts = set()
        self.processed_file = Path("processed_alerts.json")
        self._load_processed_alerts()
    
    def _load_processed_alerts(self):
        """Load previously processed alert IDs"""
        if self.processed_file.exists():
            try:
                with open(self.processed_file, 'r') as f:
                    data = json.load(f)
                    self.processed_alerts = set(data.get('processed_ids', []))
                logger.info(f"Loaded {len(self.processed_alerts)} processed alerts")
            except Exception as e:
                logger.error(f"Error loading processed alerts: {e}")
    
    def _save_processed_alerts(self):
        """Save processed alert IDs"""
        try:
            # Keep only recent alerts (last 1000)
            recent_alerts = list(self.processed_alerts)[-1000:]
            with open(self.processed_file, 'w') as f:
                json.dump({
                    'processed_ids': recent_alerts,
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving processed alerts: {e}")
    
    def test_connection(self) -> bool:
        """Test connection to Kibana"""
        try:
            url = f"{self.kibana_url}/api/status"
            response = requests.get(url, auth=self.auth, headers=self.headers, timeout=10, verify=self.verify_ssl)
            
            if response.status_code == 200:
                logger.info("✅ Successfully connected to Kibana")
                return True
            else:
                logger.error(f"❌ Failed to connect to Kibana: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"❌ Connection error: {e}")
            return False
    
    def get_detection_alerts(self, time_range: int = 5) -> List[Dict]:
        """
        Get detection alerts from Kibana Security
        
        Args:
            time_range: Time range in minutes to look back
            
        Returns:
            List of alert dictionaries
        """
        try:
            # Kibana Detection Engine API endpoint
            url = f"{self.api_base}/detection_engine/signals/search"
            
            # Calculate time range
            now = datetime.utcnow()
            from_time = now - timedelta(minutes=time_range)
            
            # Query for recent alerts
            query = {
                "query": {
                    "bool": {
                        "filter": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": from_time.isoformat(),
                                        "lte": now.isoformat()
                                    }
                                }
                            }
                        ]
                    }
                },
                "size": 100,  # Max alerts per query
                "sort": [
                    {
                        "@timestamp": {
                            "order": "desc"
                        }
                    }
                ]
            }
            
            response = requests.post(
                url,
                auth=self.auth,
                headers=self.headers,
                json=query,
                timeout=30,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                data = response.json()
                hits = data.get('hits', {}).get('hits', [])
                logger.info(f"Found {len(hits)} alerts")
                return hits
            else:
                logger.error(f"Failed to get alerts: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return []
    
    def get_alerts_via_search(self, time_range: int = 5) -> List[Dict]:
        """
        Alternative method: Get alerts via Elasticsearch search API
        
        Args:
            time_range: Time range in minutes
            
        Returns:
            List of alert dictionaries
        """
        try:
            # Use Elasticsearch search API
            url = f"{self.api_base}/console/proxy?path=/.alerts-*/_search&method=POST"
            
            now = datetime.utcnow()
            from_time = now - timedelta(minutes=time_range)
            
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": from_time.isoformat(),
                                        "lte": now.isoformat()
                                    }
                                }
                            }
                        ]
                    }
                },
                "size": 100,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            response = requests.post(
                url,
                auth=self.auth,
                headers=self.headers,
                json=query,
                timeout=30,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                data = response.json()
                hits = data.get('hits', {}).get('hits', [])
                logger.info(f"Found {len(hits)} alerts via search")
                return hits
            else:
                logger.error(f"Search failed: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Search error: {e}")
            return []
    
    def normalize_alert(self, raw_alert: Dict) -> Dict:
        """
        Normalize Kibana alert to standard format
        
        Args:
            raw_alert: Raw alert from Kibana
            
        Returns:
            Normalized alert dictionary
        """
        source = raw_alert.get('_source', {})
        
        # Extract common fields
        normalized = {
            'id': raw_alert.get('_id', 'unknown'),
            'timestamp': source.get('@timestamp', datetime.now().isoformat()),
            'kibana.alert.severity': source.get('kibana.alert.severity', 
                                               source.get('signal', {}).get('rule', {}).get('severity', 'unknown')),
            'kibana.alert.status': source.get('kibana.alert.status', 
                                             source.get('signal', {}).get('status', 'unknown')),
            'rule': {
                'name': source.get('kibana.alert.rule.name', 
                                  source.get('signal', {}).get('rule', {}).get('name', 'Unknown')),
                'description': source.get('kibana.alert.rule.description', 
                                        source.get('signal', {}).get('rule', {}).get('description', '')),
                'id': source.get('kibana.alert.rule.uuid', 
                               source.get('signal', {}).get('rule', {}).get('id', ''))
            },
            'source': {
                'ip': source.get('source.ip', source.get('source', {}).get('ip', 'unknown'))
            },
            'destination': {
                'ip': source.get('destination.ip', source.get('destination', {}).get('ip', 'unknown'))
            },
            'agent': {
                'name': source.get('agent.name', source.get('agent', {}).get('name', 'unknown'))
            },
            'raw': source  # Keep raw data for reference
        }
        
        return normalized
    
    def collect_new_alerts(self) -> List[Dict]:
        """
        Collect new alerts that haven't been processed
        
        Returns:
            List of new normalized alerts
        """
        logger.info("🔍 Collecting alerts from Kibana...")
        
        # Try detection engine first
        raw_alerts = self.get_detection_alerts()
        
        # Fallback to search if detection engine fails
        if not raw_alerts:
            logger.info("Trying alternative search method...")
            raw_alerts = self.get_alerts_via_search()
        
        # Normalize and filter new alerts
        new_alerts = []
        for raw_alert in raw_alerts:
            alert_id = raw_alert.get('_id')
            
            if alert_id not in self.processed_alerts:
                normalized = self.normalize_alert(raw_alert)
                new_alerts.append(normalized)
                self.processed_alerts.add(alert_id)
        
        if new_alerts:
            logger.info(f"✅ Found {len(new_alerts)} new alerts")
            self._save_processed_alerts()
        else:
            logger.info("No new alerts found")
        
        return new_alerts
    
    def start_polling(self, callback=None):
        """
        Start continuous polling for alerts
        
        Args:
            callback: Function to call with each new alert
        """
        logger.info(f"🚀 Starting alert collector (polling every {self.poll_interval}s)")
        
        # Test connection first
        if not self.test_connection():
            logger.error("Cannot connect to Kibana - aborting")
            return
        
        try:
            while True:
                try:
                    # Collect new alerts
                    new_alerts = self.collect_new_alerts()
                    
                    # Process each alert
                    for alert in new_alerts:
                        logger.info(f"📨 Processing alert: {alert['rule']['name']}")
                        
                        if callback:
                            try:
                                callback(alert)
                            except Exception as e:
                                logger.error(f"Error in callback: {e}")
                        
                        # Save alert to file
                        self._save_alert(alert)
                    
                    # Wait before next poll
                    logger.info(f"⏳ Waiting {self.poll_interval} seconds...")
                    time.sleep(self.poll_interval)
                    
                except KeyboardInterrupt:
                    logger.info("Stopping collector...")
                    break
                except Exception as e:
                    logger.error(f"Error in polling loop: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    time.sleep(self.poll_interval)
        
        except KeyboardInterrupt:
            logger.info("👋 Collector stopped by user")
    
    def _save_alert(self, alert: Dict):
        """Save alert to file"""
        alerts_dir = Path('collected_alerts')
        alerts_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = alerts_dir / f"alert_{timestamp}_{alert['id'][:8]}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(alert, f, indent=2, ensure_ascii=False)
            logger.info(f"💾 Saved alert to {filename}")
        except Exception as e:
            logger.error(f"Error saving alert: {e}")


# ============================================================================
# INTEGRATION WITH AGENT PLANNER
# ============================================================================

def process_alert_with_agent(alert: Dict):
    """
    Process collected alert through Agent Planner system
    """
    try:
        # Import agent planner
        try:
            from agent_planner_gemini import create_gemini_agent_workflow
            from agent_planner import AgentState
            use_gemini = True
            logger.info("🧠 Using Gemini-powered agent planner")
        except ImportError:
            from agent_planner import process_alert
            use_gemini = False
            logger.info("📋 Using rule-based agent planner")
        
        logger.info(f"🤖 Processing alert through agent planner...")
        
        if use_gemini:
            # Use Gemini workflow
            initial_state = AgentState(
                alert=alert,
                playbook={},
                messages=[],
                current_agent="planner",
                analysis_results={},
                actions_taken=[],
                next_action="",
                confidence=0.0
            )
            
            app = create_gemini_agent_workflow()
            result = app.invoke(initial_state)
            
            result_data = {
                "status": "completed",
                "alert_id": alert.get("id"),
                "playbook": result["playbook"],
                "analysis": result["analysis_results"],
                "actions": result.get("actions_taken", []),
                "confidence": result["confidence"],
                "timestamp": datetime.now().isoformat()
            }
        else:
            # Use basic workflow
            result_data = process_alert(alert)
        
        # Save result
        results_dir = Path('agent_results')
        results_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        result_file = results_dir / f"result_{timestamp}.json"
        
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"✅ Alert processed successfully")
        logger.info(f"📚 Playbook: {result_data['playbook']['name']}")
        logger.info(f"📁 Result saved to: {result_file}")
        
    except Exception as e:
        logger.error(f"❌ Error processing alert: {e}")
        import traceback
        logger.error(traceback.format_exc())


# ============================================================================
# MAIN SCRIPT
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Kibana Alert Collector')
    parser.add_argument('--url', required=True, help='Kibana URL (e.g., http://localhost:5601)')
    parser.add_argument('--username', help='Kibana username')
    parser.add_argument('--password', help='Kibana password')
    parser.add_argument('--api-key', help='Kibana API key')
    parser.add_argument('--space', default='default', help='Kibana space ID (default: default)')
    parser.add_argument('--interval', type=int, default=60, help='Poll interval in seconds (default: 60)')
    parser.add_argument('--process', action='store_true', help='Process alerts through agent planner')
    parser.add_argument('--test', action='store_true', help='Test connection only')
    parser.add_argument('--no-verify', action='store_true', help='Disable SSL certificate verification (for self-signed certs)')
    
    args = parser.parse_args()
    
    # Create collector
    collector = KibanaAlertCollector(
        kibana_url=args.url,
        username=args.username or os.getenv('KIBANA_USERNAME'),
        password=args.password or os.getenv('KIBANA_PASSWORD'),
        api_key=args.api_key or os.getenv('KIBANA_API_KEY'),
        space_id=args.space,
        poll_interval=args.interval,
        verify_ssl=not args.no_verify
    )
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║         Kibana Alert Collector - Sp4c3K                  ║
    ╚═══════════════════════════════════════════════════════════╝
    
    🔍 Collecting alerts from Kibana SIEM
    📋 No webhook required - polling alerts directly
    
    Configuration:
    • Kibana URL: {url}
    • Space: {space}
    • Poll Interval: {interval}s
    • Process Alerts: {process}
    
    Press Ctrl+C to stop
    """.format(
        url=args.url,
        space=args.space,
        interval=args.interval,
        process='Yes (with Agent Planner)' if args.process else 'No (collect only)'
    ))
    
    if args.test:
        # Test connection only
        logger.info("Testing connection to Kibana...")
        if collector.test_connection():
            logger.info("✅ Connection test successful!")
        else:
            logger.error("❌ Connection test failed!")
    else:
        # Start collecting
        callback = process_alert_with_agent if args.process else None
        collector.start_polling(callback=callback)
