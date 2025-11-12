#!/usr/bin/env python3
"""
Process real Kibana alerts through Agent Planner
"""

from kibana_collector import KibanaAlertCollector
import json
import os

# Configuration
KIBANA_URL = "https://10.8.0.13:5601"
USERNAME = "elastic"
PASSWORD = "AAA@123aaa!@#"

print("=" * 70)
print("Processing REAL Kibana Alerts with Agent Planner")
print("=" * 70)

# Create collector
collector = KibanaAlertCollector(
    kibana_url=KIBANA_URL,
    username=USERNAME,
    password=PASSWORD,
    verify_ssl=False
)

# Get alerts
print("\n🔍 Fetching alerts from last 24 hours...")
raw_alerts = collector.get_detection_alerts(time_range=1440)
print(f"✅ Found {len(raw_alerts)} alerts")

if not raw_alerts:
    print("❌ No alerts to process")
    exit(0)

# Normalize and display first alert
print("\n" + "=" * 70)
print("REAL ALERT DATA - Alert #1")
print("=" * 70)

raw_alert = raw_alerts[0]
normalized = collector.normalize_alert(raw_alert)

print("\n📋 Normalized Alert:")
print(json.dumps(normalized, indent=2))

# Save normalized alert
with open('normalized_alert.json', 'w') as f:
    json.dump(normalized, f, indent=2)
print("\n💾 Saved normalized alert to: normalized_alert.json")

# Now process through agent planner
print("\n" + "=" * 70)
print("Processing through Agent Planner")
print("=" * 70)

try:
    # Check if Gemini is available
    if os.getenv('GOOGLE_API_KEY'):
        print("\n🤖 Using Gemini AI Agent Planner")
        from agent_planner_gemini import create_gemini_agent_workflow, AgentState
        
        # Create workflow
        app = create_gemini_agent_workflow()
        
        # Process alert
        initial_state = AgentState(
            alert=normalized,
            playbook="",
            messages=[],
            analysis_results={},
            actions_taken=[],
            confidence=0.0
        )
        
        print("\n⚙️ Running agent workflow...")
        result = app.invoke(initial_state)
        
        print("\n✅ Agent Analysis Complete!")
        print(f"\n🎯 Selected Playbook: {result.get('playbook', 'N/A')}")
        print(f"📊 Confidence: {result.get('confidence', 0)*100:.1f}%")
        print(f"\n📝 Actions Taken:")
        for action in result.get('actions_taken', []):
            print(f"  • {action}")
        
        # Save result
        with open('agent_result_real.json', 'w') as f:
            json.dump({
                'alert': normalized,
                'playbook': result.get('playbook'),
                'confidence': result.get('confidence'),
                'actions': result.get('actions_taken'),
                'analysis': result.get('analysis_results')
            }, f, indent=2)
        print("\n💾 Saved agent result to: agent_result_real.json")
        
    else:
        print("\n⚠️ GOOGLE_API_KEY not set - using rule-based matching")
        from agent_planner import create_agent_workflow, AgentState
        
        # Create workflow
        app = create_agent_workflow()
        
        # Process alert
        initial_state = AgentState(
            alert=normalized,
            playbook="",
            messages=[],
            analysis_results={},
            actions_taken=[],
            confidence=0.0
        )
        
        print("\n⚙️ Running agent workflow...")
        result = app.invoke(initial_state)
        
        print("\n✅ Agent Analysis Complete!")
        print(f"\n🎯 Selected Playbook: {result.get('playbook', 'N/A')}")
        print(f"📊 Confidence: {result.get('confidence', 0)*100:.1f}%")
        print(f"\n📝 Actions Taken:")
        for action in result.get('actions_taken', []):
            print(f"  • {action}")
        
        # Save result
        with open('agent_result_real.json', 'w') as f:
            json.dump({
                'alert': normalized,
                'playbook': result.get('playbook'),
                'confidence': result.get('confidence'),
                'actions': result.get('actions_taken'),
                'analysis': result.get('analysis_results')
            }, f, indent=2)
        print("\n💾 Saved agent result to: agent_result_real.json")

except Exception as e:
    print(f"\n❌ Error processing alert: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 70)
print("Test Complete!")
print("=" * 70)
