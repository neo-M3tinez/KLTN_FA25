#!/usr/bin/env python3
"""
Test script for Security Agent Planner System
Author: Sp4c3K
"""

from datetime import datetime
import json
from pathlib import Path

# Import agent planner
from agent_planner import process_alert

# Test cases
TEST_ALERTS = {
    "brute_force": {
        "id": "alert-bf-001",
        "rule": {
            "name": "Multiple Failed SSH Login Attempts",
            "description": "Brute force attack detected - 50 failed login attempts from external IP"
        },
        "kibana.alert.severity": "high",
        "kibana.alert.status": "active",
        "source": {"ip": "203.0.113.45"},
        "destination": {"ip": "10.0.0.50"},
        "agent": {"name": "ssh-server-01"},
        "timestamp": datetime.now().isoformat()
    },
    
    "malware": {
        "id": "alert-mal-002",
        "rule": {
            "name": "Ransomware Activity Detected",
            "description": "Suspicious file encryption behavior detected on endpoint"
        },
        "kibana.alert.severity": "critical",
        "kibana.alert.status": "active",
        "source": {"ip": "10.0.1.100"},
        "agent": {"name": "workstation-42"},
        "timestamp": datetime.now().isoformat()
    },
    
    "data_exfiltration": {
        "id": "alert-exfil-003",
        "rule": {
            "name": "Unusual Large Data Transfer",
            "description": "Large data transfer detected to external server - possible exfiltration"
        },
        "kibana.alert.severity": "critical",
        "kibana.alert.status": "active",
        "source": {"ip": "10.0.2.50"},
        "destination": {"ip": "198.51.100.200"},
        "agent": {"name": "database-server-01"},
        "timestamp": datetime.now().isoformat()
    },
    
    "web_attack": {
        "id": "alert-web-004",
        "rule": {
            "name": "SQL Injection Attempt Detected",
            "description": "Multiple SQL injection patterns detected in web requests"
        },
        "kibana.alert.severity": "high",
        "kibana.alert.status": "active",
        "source": {"ip": "192.0.2.100"},
        "destination": {"ip": "10.0.3.80"},
        "agent": {"name": "web-server-01"},
        "timestamp": datetime.now().isoformat()
    },
    
    "phishing": {
        "id": "alert-phish-005",
        "rule": {
            "name": "Phishing Email Detected",
            "description": "Suspicious email with credential harvesting link detected"
        },
        "kibana.alert.severity": "medium",
        "kibana.alert.status": "active",
        "agent": {"name": "email-gateway"},
        "timestamp": datetime.now().isoformat()
    },
    
    "privilege_escalation": {
        "id": "alert-priv-006",
        "rule": {
            "name": "Unauthorized Privilege Escalation",
            "description": "User attempted to gain admin privileges without authorization"
        },
        "kibana.alert.severity": "high",
        "kibana.alert.status": "active",
        "source": {"ip": "10.0.1.75"},
        "agent": {"name": "domain-controller"},
        "timestamp": datetime.now().isoformat()
    }
}


def run_single_test(test_name: str, alert_data: dict):
    """Run a single test case"""
    print("\n" + "🔥"*40)
    print(f"TESTING: {test_name.upper()}")
    print("🔥"*40 + "\n")
    
    result = process_alert(alert_data)
    
    print("\n" + "="*80)
    print(f"TEST RESULT: {test_name.upper()}")
    print("="*80)
    print(f"✅ Status: {result['status']}")
    print(f"📚 Playbook: {result['playbook']['name']}")
    print(f"🤖 Agents: {len(result['analysis'])}")
    print(f"⚡ Actions: {len(result['actions'])}")
    print(f"✨ Confidence: {result['confidence']*100}%")
    print("="*80 + "\n")
    
    return result


def run_all_tests():
    """Run all test cases"""
    print("\n" + "🎯"*40)
    print("SECURITY AGENT PLANNER - FULL TEST SUITE")
    print("🎯"*40 + "\n")
    
    results = {}
    
    for test_name, alert_data in TEST_ALERTS.items():
        try:
            result = run_single_test(test_name, alert_data)
            results[test_name] = {
                "status": "success",
                "result": result
            }
        except Exception as e:
            print(f"\n❌ Test {test_name} FAILED: {str(e)}\n")
            results[test_name] = {
                "status": "failed",
                "error": str(e)
            }
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUITE SUMMARY")
    print("="*80)
    
    passed = sum(1 for r in results.values() if r["status"] == "success")
    total = len(results)
    
    print(f"\n✅ Passed: {passed}/{total}")
    print(f"❌ Failed: {total - passed}/{total}")
    print(f"📊 Success Rate: {(passed/total)*100:.1f}%\n")
    
    for test_name, result in results.items():
        status_icon = "✅" if result["status"] == "success" else "❌"
        print(f"{status_icon} {test_name}: {result['status']}")
        if result["status"] == "success":
            playbook = result["result"]["playbook"]["name"]
            print(f"   └─ Playbook: {playbook}")
    
    print("\n" + "="*80 + "\n")
    
    # Save summary
    summary_file = Path("test_results") / f"test_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    summary_file.parent.mkdir(exist_ok=True)
    
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "total_tests": total,
            "passed": passed,
            "failed": total - passed,
            "success_rate": (passed/total)*100,
            "results": results
        }, f, indent=2, ensure_ascii=False)
    
    print(f"📁 Test summary saved to: {summary_file}\n")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # Run specific test
        test_name = sys.argv[1]
        if test_name in TEST_ALERTS:
            run_single_test(test_name, TEST_ALERTS[test_name])
        else:
            print(f"❌ Unknown test: {test_name}")
            print(f"Available tests: {', '.join(TEST_ALERTS.keys())}")
    else:
        # Run all tests
        run_all_tests()
