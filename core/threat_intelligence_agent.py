#!/usr/bin/env python3
"""
Threat Intelligence Agent
Author: Sp4c3K
Description: Query threat intelligence sources (AbuseIPDB, VirusTotal) for IOCs
"""

import os
import json
import requests
import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class ThreatIntelligenceAgent:
    """Agent for querying threat intelligence sources"""
    
    def __init__(
        self,
        abuseipdb_key: str = None,
        virustotal_key: str = None
    ):
        """
        Initialize Threat Intelligence Agent
        
        Args:
            abuseipdb_key: AbuseIPDB API key
            virustotal_key: VirusTotal API key
        """
        self.abuseipdb_key = abuseipdb_key or os.getenv('ABUSEIPDB_API_KEY')
        self.virustotal_key = virustotal_key or os.getenv('VIRUSTOTAL_API_KEY')
        
        self.abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
        self.virustotal_url = "https://www.virustotal.com/api/v3"
        
        logger.info("Threat Intelligence Agent initialized")
        if self.abuseipdb_key:
            logger.info("✅ AbuseIPDB API key configured")
        else:
            logger.warning("⚠️  AbuseIPDB API key not configured")
            
        if self.virustotal_key:
            logger.info("✅ VirusTotal API key configured")
        else:
            logger.warning("⚠️  VirusTotal API key not configured")
    
    def check_ip_abuseipdb(self, ip_address: str) -> Dict:
        """
        Check IP reputation with AbuseIPDB
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with IP reputation data in JSON format
        """
        if not self.abuseipdb_key:
            return {
                "success": False,
                "error": "AbuseIPDB API key not configured",
                "ip": ip_address,
                "source": "abuseipdb"
            }
        
        try:
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_key
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            
            logger.info(f"🔍 Checking IP {ip_address} with AbuseIPDB...")
            response = requests.get(
                self.abuseipdb_url,
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                abuse_score = data.get('data', {}).get('abuseConfidenceScore', 0)
                total_reports = data.get('data', {}).get('totalReports', 0)
                logger.info(f"  ├─ AbuseIPDB Score: {abuse_score}% confidence")
                logger.info(f"  ├─ Total Reports: {total_reports}")
                logger.info(f"  └─ Verdict: {'🚫 MALICIOUS' if abuse_score >= 80 else '⚠️ SUSPICIOUS' if abuse_score >= 50 else '✅ CLEAN'}")
                result = {
                    "success": True,
                    "ip": ip_address,
                    "source": "abuseipdb",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {
                        "abuse_confidence_score": data['data'].get('abuseConfidenceScore', 0),
                        "country_code": data['data'].get('countryCode', 'Unknown'),
                        "usage_type": data['data'].get('usageType', 'Unknown'),
                        "isp": data['data'].get('isp', 'Unknown'),
                        "domain": data['data'].get('domain', 'Unknown'),
                        "total_reports": data['data'].get('totalReports', 0),
                        "num_distinct_users": data['data'].get('numDistinctUsers', 0),
                        "last_reported_at": data['data'].get('lastReportedAt', None),
                        "is_whitelisted": data['data'].get('isWhitelisted', False),
                        "is_public": data['data'].get('isPublic', True)
                    },
                    "verdict": self._get_ip_verdict(data['data'].get('abuseConfidenceScore', 0))
                }
                
                logger.info(f"✅ AbuseIPDB check complete: {ip_address} - Score: {result['data']['abuse_confidence_score']}")
                return result
            else:
                logger.error(f"❌ AbuseIPDB API error: {response.status_code}")
                return {
                    "success": False,
                    "error": f"API returned status {response.status_code}",
                    "ip": ip_address,
                    "source": "abuseipdb"
                }
                
        except Exception as e:
            logger.error(f"❌ AbuseIPDB check failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "ip": ip_address,
                "source": "abuseipdb"
            }
    
    def check_ip_virustotal(self, ip_address: str) -> Dict:
        """
        Check IP reputation with VirusTotal
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with IP reputation data in JSON format
        """
        if not self.virustotal_key:
            return {
                "success": False,
                "error": "VirusTotal API key not configured",
                "ip": ip_address,
                "source": "virustotal"
            }
        
        try:
            headers = {
                'x-apikey': self.virustotal_key
            }
            
            url = f"{self.virustotal_url}/ip_addresses/{ip_address}"
            
            logger.info(f"🔍 Checking IP {ip_address} with VirusTotal...")
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data['data']['attributes']
                stats = attributes.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total_vendors = sum(stats.values())
                logger.info(f"  ├─ VirusTotal: {malicious}/{total_vendors} vendors flagged as malicious")
                logger.info(f"  └─ Verdict: {'🚫 MALICIOUS' if malicious >= 5 else '⚠️ SUSPICIOUS' if malicious >= 1 else '✅ CLEAN'}")
                
                result = {
                    "success": True,
                    "ip": ip_address,
                    "source": "virustotal",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "harmless": stats.get('harmless', 0),
                        "undetected": stats.get('undetected', 0),
                        "country": attributes.get('country', 'Unknown'),
                        "asn": attributes.get('asn', 'Unknown'),
                        "as_owner": attributes.get('as_owner', 'Unknown'),
                        "reputation": attributes.get('reputation', 0),
                        "total_votes": attributes.get('total_votes', {})
                    },
                    "verdict": self._get_vt_verdict(stats)
                }
                
                logger.info(f"✅ VirusTotal check complete: {ip_address} - Malicious: {result['data']['malicious']}")
                return result
            else:
                logger.error(f"❌ VirusTotal API error: {response.status_code}")
                return {
                    "success": False,
                    "error": f"API returned status {response.status_code}",
                    "ip": ip_address,
                    "source": "virustotal"
                }
                
        except Exception as e:
            logger.error(f"❌ VirusTotal check failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "ip": ip_address,
                "source": "virustotal"
            }
    
    def check_file_hash_virustotal(self, file_hash: str) -> Dict:
        """
        Check file hash with VirusTotal
        
        Args:
            file_hash: SHA256 file hash
            
        Returns:
            Dictionary with file analysis data in JSON format
        """
        if not self.virustotal_key:
            return {
                "success": False,
                "error": "VirusTotal API key not configured",
                "hash": file_hash,
                "source": "virustotal"
            }
        
        try:
            headers = {
                'x-apikey': self.virustotal_key
            }
            
            url = f"{self.virustotal_url}/files/{file_hash}"
            
            logger.info(f"🔍 Checking file hash {file_hash[:16]}... with VirusTotal...")
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data['data']['attributes']
                stats = attributes.get('last_analysis_stats', {})
                
                result = {
                    "success": True,
                    "hash": file_hash,
                    "source": "virustotal",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "undetected": stats.get('undetected', 0),
                        "harmless": stats.get('harmless', 0),
                        "file_type": attributes.get('type_description', 'Unknown'),
                        "file_size": attributes.get('size', 0),
                        "names": attributes.get('names', [])[:5],  # First 5 names
                        "signature_info": attributes.get('signature_info', {}),
                        "reputation": attributes.get('reputation', 0)
                    },
                    "verdict": self._get_vt_verdict(stats)
                }
                
                logger.info(f"✅ VirusTotal file check complete: Malicious: {result['data']['malicious']}")
                return result
            elif response.status_code == 404:
                return {
                    "success": True,
                    "hash": file_hash,
                    "source": "virustotal",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {
                        "found": False,
                        "message": "File hash not found in VirusTotal database"
                    },
                    "verdict": "unknown"
                }
            else:
                logger.error(f"❌ VirusTotal API error: {response.status_code}")
                return {
                    "success": False,
                    "error": f"API returned status {response.status_code}",
                    "hash": file_hash,
                    "source": "virustotal"
                }
                
        except Exception as e:
            logger.error(f"❌ VirusTotal file check failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "hash": file_hash,
                "source": "virustotal"
            }
    
    def check_domain_virustotal(self, domain: str) -> Dict:
        """
        Check domain with VirusTotal
        
        Args:
            domain: Domain name to check
            
        Returns:
            Dictionary with domain analysis data in JSON format
        """
        if not self.virustotal_key:
            return {
                "success": False,
                "error": "VirusTotal API key not configured",
                "domain": domain,
                "source": "virustotal"
            }
        
        try:
            headers = {
                'x-apikey': self.virustotal_key
            }
            
            url = f"{self.virustotal_url}/domains/{domain}"
            
            logger.info(f"🔍 Checking domain {domain} with VirusTotal...")
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data['data']['attributes']
                stats = attributes.get('last_analysis_stats', {})
                
                result = {
                    "success": True,
                    "domain": domain,
                    "source": "virustotal",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "harmless": stats.get('harmless', 0),
                        "undetected": stats.get('undetected', 0),
                        "reputation": attributes.get('reputation', 0),
                        "categories": attributes.get('categories', {}),
                        "last_dns_records": attributes.get('last_dns_records', [])[:3]
                    },
                    "verdict": self._get_vt_verdict(stats)
                }
                
                logger.info(f"✅ VirusTotal domain check complete: {domain} - Malicious: {result['data']['malicious']}")
                return result
            else:
                logger.error(f"❌ VirusTotal API error: {response.status_code}")
                return {
                    "success": False,
                    "error": f"API returned status {response.status_code}",
                    "domain": domain,
                    "source": "virustotal"
                }
                
        except Exception as e:
            logger.error(f"❌ VirusTotal domain check failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "domain": domain,
                "source": "virustotal"
            }
    
    def analyze_iocs(self, alert: Dict) -> Dict:
        """
        Analyze all IOCs (Indicators of Compromise) from alert
        
        Args:
            alert: Alert dictionary
            
        Returns:
            Dictionary with all TI results in JSON format
        """
        logger.info("="*80)
        logger.info("🔍 THREAT INTELLIGENCE ANALYSIS")
        logger.info("="*80)
        
        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "alert_id": alert.get('id', 'unknown'),
            "ti_checked": True,
            "ips": [],
            "domains": [],
            "hashes": [],
            "overall_verdict": "unknown"
        }
        
        # Extract and check IPs
        ips_to_check = []
        if alert.get('source', {}).get('ip') and alert['source']['ip'] != 'unknown':
            ips_to_check.append(alert['source']['ip'])
        if alert.get('destination', {}).get('ip') and alert['destination']['ip'] != 'unknown':
            ips_to_check.append(alert['destination']['ip'])
        
        # Check raw data for IPs
        raw = alert.get('raw', {})
        if raw.get('transaction.client_ip'):
            ips_to_check.append(raw['transaction.client_ip'])
        
        for ip in set(ips_to_check):  # Remove duplicates
            logger.info(f"\n🌐 Checking IP: {ip}")
            
            ip_result = {
                "ip": ip,
                "abuseipdb": self.check_ip_abuseipdb(ip),
                "virustotal": self.check_ip_virustotal(ip)
            }
            
            # Determine overall IP verdict
            verdicts = []
            if ip_result['abuseipdb']['success']:
                verdicts.append(ip_result['abuseipdb']['verdict'])
            if ip_result['virustotal']['success']:
                verdicts.append(ip_result['virustotal']['verdict'])
            
            ip_result['verdict'] = self._determine_overall_verdict(verdicts)
            results['ips'].append(ip_result)
        
        # Extract and check domains
        domains_to_check = []
        if alert.get('destination', {}).get('domain'):
            domains_to_check.append(alert['destination']['domain'])
        
        for domain in set(domains_to_check):
            logger.info(f"\n🌍 Checking Domain: {domain}")
            
            domain_result = {
                "domain": domain,
                "virustotal": self.check_domain_virustotal(domain),
                "verdict": "unknown"
            }
            
            if domain_result['virustotal']['success']:
                domain_result['verdict'] = domain_result['virustotal']['verdict']
            
            results['domains'].append(domain_result)
        
        # Extract and check file hashes
        hashes_to_check = []
        if alert.get('file', {}).get('hash', {}).get('sha256'):
            hashes_to_check.append(alert['file']['hash']['sha256'])
        
        for file_hash in set(hashes_to_check):
            logger.info(f"\n📄 Checking File Hash: {file_hash[:16]}...")
            
            hash_result = {
                "hash": file_hash,
                "virustotal": self.check_file_hash_virustotal(file_hash),
                "verdict": "unknown"
            }
            
            if hash_result['virustotal']['success']:
                hash_result['verdict'] = hash_result['virustotal']['verdict']
            
            results['hashes'].append(hash_result)
        
        # Determine overall verdict
        all_verdicts = []
        for ip_result in results['ips']:
            all_verdicts.append(ip_result['verdict'])
        for domain_result in results['domains']:
            all_verdicts.append(domain_result['verdict'])
        for hash_result in results['hashes']:
            all_verdicts.append(hash_result['verdict'])
        
        results['overall_verdict'] = self._determine_overall_verdict(all_verdicts)
        
        logger.info("\n" + "="*80)
        logger.info(f"✅ Threat Intelligence Analysis Complete")
        logger.info(f"📊 Overall Verdict: {results['overall_verdict'].upper()}")
        logger.info("="*80)
        
        return results
    
    def _get_ip_verdict(self, abuse_score: int) -> str:
        """Determine verdict based on AbuseIPDB score"""
        if abuse_score >= 75:
            return "malicious"
        elif abuse_score >= 50:
            return "suspicious"
        elif abuse_score >= 25:
            return "potentially_malicious"
        else:
            return "clean"
    
    def _get_vt_verdict(self, stats: Dict) -> str:
        """Determine verdict based on VirusTotal stats"""
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        if malicious >= 5:
            return "malicious"
        elif malicious >= 2 or suspicious >= 5:
            return "suspicious"
        elif malicious >= 1 or suspicious >= 1:
            return "potentially_malicious"
        else:
            return "clean"
    
    def _determine_overall_verdict(self, verdicts: List[str]) -> str:
        """Determine overall verdict from multiple sources"""
        if not verdicts:
            return "unknown"
        
        if "malicious" in verdicts:
            return "malicious"
        elif "suspicious" in verdicts:
            return "suspicious"
        elif "potentially_malicious" in verdicts:
            return "potentially_malicious"
        elif "clean" in verdicts:
            return "clean"
        else:
            return "unknown"


# Test function
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Test with sample data
    ti_agent = ThreatIntelligenceAgent()
    
    sample_alert = {
        "id": "test-123",
        "source": {"ip": "8.8.8.8"},
        "destination": {"ip": "1.1.1.1"},
        "raw": {"transaction.client_ip": "196.251.86.122"}
    }
    
    results = ti_agent.analyze_iocs(sample_alert)
    print("\n" + "="*80)
    print("RESULTS:")
    print(json.dumps(results, indent=2))
