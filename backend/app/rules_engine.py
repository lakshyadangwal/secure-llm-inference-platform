import json
import logging
import re
import os
import uuid
from typing import List, Dict

logger = logging.getLogger(__name__)

DB_FILE = os.path.join(os.path.dirname(__file__), "..", "rules_db.json")

class DynamicRulesEngine:
    """
    Dynamic Rules Engine allowing admins to inject real-time Regex and Keyword 
    blocking rules without restarting the server.
    """
    def __init__(self):
        self.rules = []
        self._load_rules()
        
    def _load_rules(self):
        if os.path.exists(DB_FILE):
            try:
                with open(DB_FILE, 'r') as f:
                    self.rules = json.load(f)
                logger.info(f"✅ Loaded {len(self.rules)} dynamic rules from DB.")
            except Exception as e:
                logger.error(f"❌ Failed to load rules DB: {e}")
                self._init_default_rules()
        else:
            self._init_default_rules()

    def _init_default_rules(self):
        self.rules = [
            {
                "id": str(uuid.uuid4()),
                "name": "Default Jailbreak Block",
                "type": "regex",
                "pattern": "(?i)(ignore previous|do anything now|ignore all)",
                "action": "block",
                "active": True
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Default Data Extraction Block",
                "type": "keyword",
                "pattern": "system prompt,credentials,api key",
                "action": "block",
                "active": True
            }
        ]
        self._save_rules()
        
    def _save_rules(self):
        try:
            with open(DB_FILE, 'w') as f:
                json.dump(self.rules, f, indent=2)
        except Exception as e:
            logger.error(f"❌ Failed to save rules DB: {e}")

    def get_all(self):
        return self.rules
        
    def add_rule(self, name: str, rule_type: str, pattern: str, action: str = "block") -> dict:
        rule = {
            "id": str(uuid.uuid4()),
            "name": name,
            "type": rule_type,
            "pattern": pattern,
            "action": action,
            "active": True
        }
        self.rules.append(rule)
        self._save_rules()
        logger.info(f"🛡️ Added new dynamic rule: {name} ({rule_type})")
        return rule
        
    def delete_rule(self, rule_id: str):
        self.rules = [r for r in self.rules if r["id"] != rule_id]
        self._save_rules()
        logger.info(f"🗑️ Deleted rule ID: {rule_id}")

    def evaluate(self, text: str) -> dict:
        """
        Evaluates text against all active rules.
        Returns {"is_threat": bool, "matched_rule_name": str}
        """
        if not text:
            return {"is_threat": False, "matched_rule_name": None}
            
        for rule in self.rules:
            if not rule.get("active", True):
                continue
                
            if rule["type"] == "regex":
                try:
                    if re.search(rule["pattern"], text):
                        logger.warning(f"🚨 Rule Match [Regex]: {rule['name']}")
                        return {"is_threat": True, "matched_rule_name": rule["name"]}
                except re.error:
                    logger.error(f"Invalid regex pattern in rule {rule['name']}: {rule['pattern']}")
                    
            elif rule["type"] == "keyword":
                keywords = [k.strip().lower() for k in rule["pattern"].split(",")]
                text_lower = text.lower()
                for keyword in keywords:
                    if keyword and keyword in text_lower:
                        logger.warning(f"🚨 Rule Match [Keyword]: {rule['name']} (Matched '{keyword}')")
                        return {"is_threat": True, "matched_rule_name": rule["name"]}
                        
        return {"is_threat": False, "matched_rule_name": None}

rules_engine = DynamicRulesEngine()
