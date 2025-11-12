#!/usr/bin/env python3
"""
Playbook Loader
Author: Sp4c3K
Description: Load and manage playbooks from YAML files
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class PlaybookLoader:
    """Load and manage playbooks from YAML files"""
    
    def __init__(self, playbooks_dir: str = None):
        """
        Initialize Playbook Loader
        
        Args:
            playbooks_dir: Directory containing playbook YAML files
        """
        if playbooks_dir:
            self.playbooks_dir = Path(playbooks_dir)
        else:
            # Default to playbooks/ directory relative to this file
            self.playbooks_dir = Path(__file__).parent.parent / "playbooks"
        
        self.playbooks = {}
        self.load_all_playbooks()
    
    def load_all_playbooks(self) -> Dict:
        """
        Load all playbook YAML files from directory
        
        Returns:
            Dictionary of playbooks
        """
        if not self.playbooks_dir.exists():
            logger.error(f"❌ Playbooks directory not found: {self.playbooks_dir}")
            return {}
        
        logger.info(f"📚 Loading playbooks from: {self.playbooks_dir}")
        
        for yaml_file in self.playbooks_dir.glob("*.yml"):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    playbook = yaml.safe_load(f)
                
                playbook_id = yaml_file.stem  # Filename without extension
                self.playbooks[playbook_id] = playbook
                
                logger.info(f"✅ Loaded playbook: {playbook.get('name', playbook_id)}")
                
            except Exception as e:
                logger.error(f"❌ Failed to load {yaml_file.name}: {str(e)}")
        
        logger.info(f"📚 Total playbooks loaded: {len(self.playbooks)}")
        return self.playbooks
    
    def get_playbook(self, playbook_id: str) -> Optional[Dict]:
        """
        Get specific playbook by ID
        
        Args:
            playbook_id: Playbook identifier
            
        Returns:
            Playbook dictionary or None
        """
        return self.playbooks.get(playbook_id)
    
    def match_playbook(self, alert: Dict) -> tuple[str, float]:
        """
        Match alert to best playbook using keyword scoring
        
        Args:
            alert: Alert dictionary
            
        Returns:
            Tuple of (playbook_id, confidence_score)
        """
        alert_text = self._extract_alert_text(alert).lower()
        severity = alert.get('kibana.alert.severity', 'medium').lower()
        
        best_match = None
        best_score = 0.0
        
        for playbook_id, playbook in self.playbooks.items():
            score = 0.0
            
            # Keyword matching
            keywords = playbook.get('keywords', [])
            for keyword in keywords:
                if keyword.lower() in alert_text:
                    score += 5.0
            
            # Severity boost
            playbook_severity = playbook.get('severity', 'medium').lower()
            if severity == playbook_severity:
                score += 2.0
            
            # Normalize score
            if len(keywords) > 0:
                score = score / (len(keywords) * 5.0 + 2.0)
            
            if score > best_score:
                best_score = score
                best_match = playbook_id
        
        if best_match:
            logger.info(f"🎯 Matched playbook: {self.playbooks[best_match]['name']} (confidence: {best_score:.2%})")
            return best_match, best_score
        else:
            logger.warning("⚠️  No playbook match found, using default")
            return "default", 0.0
    
    def _extract_alert_text(self, alert: Dict) -> str:
        """Extract searchable text from alert"""
        text_parts = []
        
        # Rule name and description
        if alert.get('rule', {}).get('name'):
            text_parts.append(alert['rule']['name'])
        if alert.get('rule', {}).get('description'):
            text_parts.append(alert['rule']['description'])
        
        # Alert reason
        if alert.get('raw', {}).get('kibana.alert.reason'):
            text_parts.append(alert['raw']['kibana.alert.reason'])
        
        return ' '.join(text_parts)
    
    def list_playbooks(self) -> List[Dict]:
        """
        Get list of all available playbooks
        
        Returns:
            List of playbook summaries
        """
        return [
            {
                "id": playbook_id,
                "name": playbook.get('name'),
                "description": playbook.get('description'),
                "severity": playbook.get('severity'),
                "keywords": playbook.get('keywords', [])
            }
            for playbook_id, playbook in self.playbooks.items()
        ]


# Test function
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    loader = PlaybookLoader()
    
    print("\n" + "="*80)
    print("Available Playbooks:")
    print("="*80)
    
    for playbook_info in loader.list_playbooks():
        print(f"\n📋 {playbook_info['name']}")
        print(f"   ID: {playbook_info['id']}")
        print(f"   Severity: {playbook_info['severity']}")
        print(f"   Keywords: {', '.join(playbook_info['keywords'][:5])}")
