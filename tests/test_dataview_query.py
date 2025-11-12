"""
Test querying events from Kibana Data View
"""
import sys
import os
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.siem_query_agent import SIEMQueryAgent

def main():
    print("="*80)
    print("TESTING DATA VIEW QUERY")
    print("="*80)
    
    # Initialize SIEM agent
    siem_agent = SIEMQueryAgent(
        kibana_url="https://10.8.0.13:5601",
        username="elastic",
        password="AAA@123aaa!@#",
        verify_ssl=False
    )
    
    # Test 1: Get all events from last 15 minutes
    print("\n[Test 1] Query all events from last 15 minutes...")
    result1 = siem_agent.query_data_view(
        data_view_id="31d5c87e-5754-4471-9988-74841088eb7e",
        query="*",
        timerange="15m",
        size=10
    )
    
    print(f"\n✓ Total hits: {result1.get('total_hits', 0)}")
    print(f"✓ Returned hits: {result1.get('returned_hits', 0)}")
    if result1.get('results'):
        print(f"✓ First event timestamp: {result1['results'][0].get('@timestamp', 'N/A')}")
    
    # Test 2: Query high severity events
    print("\n[Test 2] Query high severity events...")
    result2 = siem_agent.query_data_view(
        data_view_id="31d5c87e-5754-4471-9988-74841088eb7e",
        query="event.severity:high OR kibana.alert.severity:high",
        timerange="24h",
        size=10
    )
    
    print(f"\n✓ Total hits: {result2.get('total_hits', 0)}")
    print(f"✓ Returned hits: {result2.get('returned_hits', 0)}")
    
    # Test 3: Query specific IP
    print("\n[Test 3] Query events from IP 196.251.86.122...")
    result3 = siem_agent.query_data_view(
        data_view_id="31d5c87e-5754-4471-9988-74841088eb7e",
        query="source.ip:196.251.86.122",
        timerange="24h",
        size=5
    )
    
    print(f"\n✓ Total hits: {result3.get('total_hits', 0)}")
    print(f"✓ Returned hits: {result3.get('returned_hits', 0)}")
    
    # Display sample results from Test 1
    if result1.get('results'):
        print("\n" + "="*80)
        print("SAMPLE RESULTS FROM LAST 15 MINUTES:")
        print("="*80)
        for i, event in enumerate(result1['results'][:3], 1):
            print(f"\n--- Event {i} ---")
            print(f"Timestamp: {event.get('@timestamp', 'N/A')}")
            print(f"Event Action: {event.get('event', {}).get('action', 'N/A')}")
            print(f"Source IP: {event.get('source', {}).get('ip', 'N/A')}")
            print(f"Message: {event.get('message', 'N/A')[:200]}")
        
        print("\n" + "="*80)
        print("FULL JSON OF FIRST EVENT:")
        print("="*80)
        print(json.dumps(result1['results'][0], indent=2, ensure_ascii=False))
    
    print("\n" + "="*80)
    print("✅ ALL TESTS COMPLETED")
    print("="*80)

if __name__ == "__main__":
    main()
