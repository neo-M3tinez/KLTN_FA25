"""
Test script to fetch 1 alert from Kibana and run through the complete workflow
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kibana_collector import KibanaAlertCollector
from core.enhanced_agent_workflow import process_alert
import json

def main():
    print("="*80)
    print("TESTING SINGLE ALERT THROUGH COMPLETE WORKFLOW")
    print("="*80)
    
    # Step 1: Load alert from saved file
    print("\n[1] Loading alert from normalized_alert.json...")
    try:
        with open('normalized_alert.json', 'r', encoding='utf-8') as f:
            alert = json.load(f)
        print(f"✓ Alert loaded successfully")
    except FileNotFoundError:
        print("✗ normalized_alert.json not found!")
        print("   Run 'python tests/test_real_kibana.py' first to fetch alerts")
        return
    except Exception as e:
        print(f"✗ Error loading alert: {e}")
        return
    print(f"\n[2] Processing alert: {alert.get('alert_name', 'Unknown')}")
    print(f"   - Severity: {alert.get('severity', 'Unknown')}")
    print(f"   - Timestamp: {alert.get('timestamp', 'Unknown')}")
    
    # Step 2: Process through workflow
    print("\n[3] Running through enhanced workflow...")
    print("   - Planner Agent (load playbook, set ti_checked=False)")
    print("   - TI Agent (check IOCs, set ti_checked=True)")
    print("   - Forensic Agent (run SIEM queries + Gemini analysis)")
    print("   - Response Agent (recommend actions)")
    
    try:
        result = process_alert(alert)
        
        print("\n[4] ✓ WORKFLOW COMPLETED!")
        print("="*80)
        print("RESULT (JSON):")
        print("="*80)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
        # Save result to file
        output_file = "workflow_result.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\n✓ Result saved to: {output_file}")
        
    except Exception as e:
        print(f"\n✗ Error during workflow: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
