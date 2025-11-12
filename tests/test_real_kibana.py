#!/usr/bin/env python3
"""
Test script to collect real alerts from Kibana
"""

from kibana_collector import KibanaAlertCollector
import json

# Configuration
KIBANA_URL = "https://10.8.0.13:5601"
USERNAME = "elastic"
PASSWORD = "AAA@123aaa!@#"

print("=" * 60)
print("Testing Kibana Alert Collector with REAL DATA")
print("=" * 60)

# Create collector
collector = KibanaAlertCollector(
    kibana_url=KIBANA_URL,
    username=USERNAME,
    password=PASSWORD,
    verify_ssl=False
)

# Test different time ranges
time_ranges = [
    (5, "last 5 minutes"),
    (60, "last hour"),
    (1440, "last 24 hours"),
    (10080, "last 7 days")
]

for minutes, description in time_ranges:
    print(f"\n{'='*60}")
    print(f"🔍 Searching for alerts in {description}...")
    print(f"{'='*60}")
    
    alerts = collector.get_detection_alerts(time_range=minutes)
    
    if alerts:
        print(f"✅ Found {len(alerts)} alerts!\n")
        
        # Display first 3 alerts
        for i, alert in enumerate(alerts[:3]):
            print(f"📋 Alert #{i+1}:")
            print(f"  • ID: {alert.get('id', 'N/A')}")
            print(f"  • Rule: {alert.get('rule_name', 'N/A')}")
            print(f"  • Severity: {alert.get('severity', 'N/A')}")
            print(f"  • Timestamp: {alert.get('timestamp', 'N/A')}")
            print(f"  • Source IP: {alert.get('source_ip', 'N/A')}")
            print(f"  • Dest IP: {alert.get('dest_ip', 'N/A')}")
            print(f"  • Description: {alert.get('description', 'N/A')[:100]}...")
            print()
        
        if len(alerts) > 3:
            print(f"... and {len(alerts) - 3} more alerts")
        
        # Save to file
        output_file = f"real_alerts_{minutes}min.json"
        with open(output_file, 'w') as f:
            json.dump(alerts, f, indent=2)
        print(f"💾 Saved all alerts to: {output_file}")
        
        # Stop after finding alerts
        break
    else:
        print(f"❌ No alerts found in {description}")

print("\n" + "="*60)
print("Test completed!")
print("="*60)
