#!/usr/bin/env python3
"""
SIEM Query Agent
Author: Sp4c3K
Description: Execute queries against Kibana/Elasticsearch for forensic investigation
"""

import os
import json
import requests
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)


class SIEMQueryAgent:
    """Agent for querying Kibana/Elasticsearch"""
    
    def __init__(
        self,
        kibana_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
        elasticsearch_url: Optional[str] = None
    ):
        """
        Initialize SIEM Query Agent
        
        Args:
            kibana_url: Kibana base URL
            username: Kibana username
            password: Kibana password  
            api_key: Kibana API key
            verify_ssl: Verify SSL certificates
            elasticsearch_url: Elasticsearch URL (defaults to kibana_url:9200)
        """
        self.kibana_url = kibana_url.rstrip('/')
        self.verify_ssl = verify_ssl
        
        # Setup Elasticsearch URL
        if elasticsearch_url:
            self.es_url = elasticsearch_url.rstrip('/')
        else:
            # Default: replace 5601 with 9200
            self.es_url = self.kibana_url.replace(':5601', ':9200')
        
        # Disable SSL warnings if needed
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
        
        logger.info(f"SIEM Query Agent initialized: {kibana_url}")
    
    def execute_query(
        self,
        query: str,
        timerange: str = "1h",
        index: str = "*",
        size: int = 100
    ) -> Dict:
        """
        Execute Elasticsearch query via Kibana
        
        Args:
            query: Lucene/KQL query string
            timerange: Time range (e.g., "1h", "24h", "7d")
            index: Index pattern to search
            size: Maximum number of results
            
        Returns:
            Dictionary with query results in JSON format
        """
        try:
            # Parse timerange
            now = datetime.utcnow()
            from_time = self._parse_timerange(timerange, now)
            
            # Build Elasticsearch query
            es_query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "query_string": {
                                    "query": query,
                                    "analyze_wildcard": True
                                }
                            },
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": from_time.isoformat(),
                                        "lte": now.isoformat(),
                                        "format": "strict_date_optional_time"
                                    }
                                }
                            }
                        ]
                    }
                },
                "size": size,
                "sort": [
                    {"@timestamp": {"order": "desc"}}
                ]
            }
            
            # Execute via Elasticsearch directly
            url = f"{self.es_url}/{index}/_search"
            
            logger.info(f"🔍 Executing query: {query}")
            logger.info(f"📅 Timerange: {timerange} ({from_time.isoformat()} to {now.isoformat()})")
            
            # Use simple headers for ES
            es_headers = {'Content-Type': 'application/json'}
            
            response = requests.post(
                url,
                auth=self.auth,
                headers=es_headers,
                json=es_query,
                timeout=30,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                data = response.json()
                hits = data.get('hits', {}).get('hits', [])
                
                result = {
                    "success": True,
                    "query": query,
                    "timerange": timerange,
                    "timestamp": datetime.utcnow().isoformat(),
                    "total_hits": data.get('hits', {}).get('total', {}).get('value', 0),
                    "returned_hits": len(hits),
                    "results": [hit['_source'] for hit in hits],
                    "raw_hits": hits
                }
                
                logger.info(f"✅ Query complete: {result['total_hits']} total hits, returned {result['returned_hits']}")
                return result
            else:
                logger.error(f"❌ Query failed: {response.status_code}")
                return {
                    "success": False,
                    "error": f"API returned status {response.status_code}",
                    "query": query,
                    "response_text": response.text[:500]
                }
                
        except Exception as e:
            logger.error(f"❌ Query execution failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "query": query
            }
    
    def execute_playbook_queries(
        self,
        playbook: Dict,
        alert: Dict
    ) -> Dict:
        """
        Execute all SIEM queries defined in a playbook
        
        Args:
            playbook: Playbook dictionary with siem_queries
            alert: Alert data for parameter substitution
            
        Returns:
            Dictionary with all query results in JSON format
        """
        logger.info("="*80)
        logger.info(f"🔍 EXECUTING SIEM QUERIES FROM PLAYBOOK: {playbook.get('name', 'Unknown')}")
        logger.info("="*80)
        
        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "playbook": playbook.get('name'),
            "alert_id": alert.get('id'),
            "queries": []
        }
        
        siem_queries = playbook.get('siem_queries', [])
        
        if not siem_queries:
            logger.warning("⚠️  No SIEM queries defined in playbook")
            return results
        
        for query_def in siem_queries:
            query_name = query_def.get('name', 'Unnamed Query')
            query_template = query_def.get('query', '')
            timerange = query_def.get('timerange', '1h')
            
            logger.info(f"\n📊 Query: {query_name}")
            
            # Substitute parameters from alert
            query = self._substitute_params(query_template, alert)
            
            logger.info(f"🔎 Resolved query: {query}")
            
            # Execute query
            query_result = self.execute_query(query, timerange=timerange)
            
            results['queries'].append({
                "name": query_name,
                "query": query,
                "timerange": timerange,
                "success": query_result.get('success', False),
                "total_hits": query_result.get('total_hits', 0),
                "results": query_result.get('results', [])[:10],  # First 10 results
                "error": query_result.get('error') if not query_result.get('success') else None
            })
        
        logger.info("\n" + "="*80)
        logger.info(f"✅ SIEM Query Execution Complete: {len(results['queries'])} queries executed")
        logger.info("="*80)
        
        return results
    
    def _substitute_params(self, query_template: str, alert: Dict) -> str:
        """
        Substitute parameters in query template with alert data
        
        Args:
            query_template: Query template with {param} placeholders
            alert: Alert data
            
        Returns:
            Query string with substituted parameters
        """
        # Extract source IP from various possible fields
        source_ip = alert.get('source', {}).get('ip', 'unknown')
        if source_ip == 'unknown':
            # Try raw.transaction.client_ip
            source_ip = alert.get('raw', {}).get('transaction.client_ip', 'unknown')
        if source_ip == 'unknown':
            # Try threshold_result
            threshold_terms = alert.get('raw', {}).get('kibana.alert.threshold_result', {}).get('terms', [])
            for term in threshold_terms:
                if term.get('field') == 'transaction.client_ip':
                    source_ip = term.get('value', 'unknown')
                    break
        
        # Extract common parameters from alert
        params = {
            'source_ip': source_ip,
            'dest_ip': alert.get('destination', {}).get('ip', 'unknown'),
            'destination_ip': alert.get('destination', {}).get('ip', 'unknown'),
            'host_name': alert.get('agent', {}).get('name', 'unknown'),
            'user_name': alert.get('user', {}).get('name', 'unknown'),
            'file_hash': alert.get('file', {}).get('hash', {}).get('sha256', ''),
            'file_name': alert.get('file', {}).get('name', ''),
            'process_name': alert.get('process', {}).get('name', ''),
            'rule_name': alert.get('rule', {}).get('name', ''),
        }
        
        # Check raw data for additional params
        raw = alert.get('raw', {})
        if raw.get('transaction.client_ip'):
            params['client_ip'] = raw['transaction.client_ip']
        
        # Substitute all parameters
        query = query_template
        for key, value in params.items():
            placeholder = '{' + key + '}'
            if placeholder in query:
                query = query.replace(placeholder, str(value))
        
        return query
    
    def _parse_timerange(self, timerange: str, now: datetime) -> datetime:
        """
        Parse timerange string to datetime
        
        Args:
            timerange: Time range string (e.g., "1h", "24h", "7d")
            now: Current datetime
            
        Returns:
            Datetime for start of range
        """
        if timerange.endswith('h'):
            hours = int(timerange[:-1])
            return now - timedelta(hours=hours)
        elif timerange.endswith('d'):
            days = int(timerange[:-1])
            return now - timedelta(days=days)
        elif timerange.endswith('m'):
            minutes = int(timerange[:-1])
            return now - timedelta(minutes=minutes)
        else:
            # Default to 1 hour
            return now - timedelta(hours=1)
    
    def query_data_view(
        self,
        data_view_id: str = "31d5c87e-5754-4471-9988-74841088eb7e",
        query: str = "*",
        timerange: str = "15m",
        size: int = 100,
        sort_field: str = "@timestamp",
        sort_order: str = "desc"
    ) -> Dict:
        """
        Query events from a specific Kibana Data View
        
        Args:
            data_view_id: Kibana Data View ID
            query: KQL query string (e.g., 'source.ip:1.2.3.4 AND event.severity:high')
            timerange: Time range (e.g., '15m', '1h', '24h')
            size: Maximum number of results to return
            sort_field: Field to sort by (default: @timestamp)
            sort_order: Sort order 'asc' or 'desc'
            
        Returns:
            Dict with query results
        """
        try:
            # Parse timerange
            now = datetime.utcnow()
            from_time = self._parse_timerange(timerange, now)
            
            # Build Elasticsearch query with KQL
            es_query = {
                "query": {
                    "bool": {
                        "must": [],
                        "filter": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": from_time.isoformat(),
                                        "lte": now.isoformat(),
                                        "format": "strict_date_optional_time"
                                    }
                                }
                            }
                        ]
                    }
                },
                "size": size,
                "sort": [
                    {sort_field: {"order": sort_order}}
                ]
            }
            
            # Add KQL query if not wildcard
            if query and query != "*":
                es_query["query"]["bool"]["must"].append({
                    "query_string": {
                        "query": query,
                        "analyze_wildcard": True,
                        "default_field": "*"
                    }
                })
            
            # Get index pattern from data view
            url = f"{self.kibana_url}/api/data_views/data_view/{data_view_id}"
            
            logger.info(f"🔍 Querying Data View: {data_view_id}")
            logger.info(f"📝 KQL Query: {query}")
            logger.info(f"📅 Timerange: {timerange} ({from_time.isoformat()} to {now.isoformat()})")
            
            # Get data view details
            dv_response = requests.get(
                url,
                auth=self.auth,
                headers=self.headers,
                timeout=10,
                verify=self.verify_ssl
            )
            
            if dv_response.status_code == 200:
                data_view = dv_response.json()
                index_pattern = data_view.get('data_view', {}).get('title', '*')
                logger.info(f"📊 Index Pattern: {index_pattern}")
            else:
                # Fallback to default index
                index_pattern = "*"
                logger.warning(f"⚠️ Could not fetch data view, using default index: *")
            
            # Execute search directly to Elasticsearch
            search_url = f"{self.es_url}/{index_pattern}/_search"
            
            # Use simple headers for ES
            es_headers = {'Content-Type': 'application/json'}
            
            response = requests.post(
                search_url,
                auth=self.auth,
                headers=es_headers,
                json=es_query,
                timeout=30,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                data = response.json()
                hits = data.get('hits', {}).get('hits', [])
                
                result = {
                    "success": True,
                    "data_view_id": data_view_id,
                    "index_pattern": index_pattern,
                    "query": query,
                    "timerange": timerange,
                    "timestamp": datetime.utcnow().isoformat(),
                    "total_hits": data.get('hits', {}).get('total', {}).get('value', 0),
                    "returned_hits": len(hits),
                    "results": [hit['_source'] for hit in hits],
                    "raw_hits": hits
                }
                
                logger.info(f"✅ Query complete: {result['total_hits']} total hits, returned {result['returned_hits']}")
                return result
            else:
                logger.error(f"❌ Query failed: {response.status_code} - {response.text}")
                return {
                    "success": False,
                    "error": f"Query failed with status {response.status_code}",
                    "response": response.text,
                    "data_view_id": data_view_id,
                    "query": query
                }
                
        except Exception as e:
            logger.error(f"❌ Error querying data view: {e}")
            return {
                "success": False,
                "error": str(e),
                "data_view_id": data_view_id,
                "query": query
            }


# Test function
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Test with sample data
    siem_agent = SIEMQueryAgent(
        kibana_url="https://10.8.0.13:5601",
        username="elastic",
        password="AAA@123aaa!@#",
        verify_ssl=False
    )
    
    # Test query
    result = siem_agent.execute_query(
        query="source.ip:196.251.86.122",
        timerange="24h"
    )
    
    print("\n" + "="*80)
    print("RESULTS:")
    print(json.dumps(result, indent=2)[:2000])
