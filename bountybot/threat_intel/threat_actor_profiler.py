"""
Threat Actor Profiler

Profiles threat actors and attributes attacks.
"""

import secrets
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import json

from .models import ThreatActor


class ThreatActorProfiler:
    """Threat actor profiling and attribution engine."""
    
    def __init__(self, data_dir: str = "./threat_actors"):
        """
        Initialize threat actor profiler.
        
        Args:
            data_dir: Directory for threat actor data
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.actors: Dict[str, ThreatActor] = {}
        
        # Load actors
        self._load_actors()
        
        # Initialize with sample APT groups
        self._initialize_sample_actors()
    
    def get_actor(self, actor_id: str) -> Optional[ThreatActor]:
        """
        Get threat actor by ID.
        
        Args:
            actor_id: Actor identifier
            
        Returns:
            ThreatActor or None
        """
        return self.actors.get(actor_id)
    
    def search_actors(
        self,
        actor_type: Optional[str] = None,
        sophistication: Optional[str] = None,
        target_industry: Optional[str] = None,
        target_country: Optional[str] = None
    ) -> List[ThreatActor]:
        """
        Search threat actors.
        
        Args:
            actor_type: Filter by actor type
            sophistication: Filter by sophistication level
            target_industry: Filter by target industry
            target_country: Filter by target country
            
        Returns:
            List of matching actors
        """
        results = []
        
        for actor in self.actors.values():
            if actor_type and actor.actor_type != actor_type:
                continue
            
            if sophistication and actor.sophistication != sophistication:
                continue
            
            if target_industry and target_industry not in actor.target_industries:
                continue
            
            if target_country and target_country not in actor.target_countries:
                continue
            
            results.append(actor)
        
        return results
    
    def attribute_attack(
        self,
        techniques: List[str],
        tools: List[str],
        target_industry: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Attribute attack to threat actors.
        
        Args:
            techniques: MITRE ATT&CK techniques used
            tools: Tools/malware used
            target_industry: Target industry
            
        Returns:
            List of potential threat actors with confidence scores
        """
        attributions = []
        
        for actor in self.actors.values():
            confidence = 0.0
            matches = []
            
            # Match techniques
            technique_matches = set(techniques) & set(actor.techniques)
            if technique_matches:
                confidence += (len(technique_matches) / len(techniques)) * 0.4
                matches.append(f"{len(technique_matches)} technique matches")
            
            # Match tools
            tool_matches = set(tools) & set(actor.tools + actor.malware)
            if tool_matches:
                confidence += (len(tool_matches) / len(tools)) * 0.4 if tools else 0
                matches.append(f"{len(tool_matches)} tool matches")
            
            # Match target industry
            if target_industry and target_industry in actor.target_industries:
                confidence += 0.2
                matches.append("Target industry match")
            
            if confidence > 0.0:
                attributions.append({
                    'actor_id': actor.actor_id,
                    'name': actor.name,
                    'confidence': min(confidence, 1.0),
                    'matches': matches,
                    'actor_type': actor.actor_type,
                    'sophistication': actor.sophistication
                })
        
        # Sort by confidence
        attributions.sort(key=lambda x: x['confidence'], reverse=True)
        
        return attributions
    
    def get_actor_profile(self, actor_id: str) -> Dict[str, Any]:
        """
        Get detailed actor profile.
        
        Args:
            actor_id: Actor identifier
            
        Returns:
            Actor profile
        """
        actor = self.get_actor(actor_id)
        
        if not actor:
            return {'error': 'Actor not found'}
        
        return {
            'actor_id': actor.actor_id,
            'name': actor.name,
            'aliases': actor.aliases,
            'actor_type': actor.actor_type,
            'sophistication': actor.sophistication,
            'techniques': actor.techniques,
            'tools': actor.tools,
            'malware': actor.malware,
            'target_industries': actor.target_industries,
            'target_countries': actor.target_countries,
            'attributed_campaigns': actor.attributed_campaigns,
            'confidence': actor.confidence,
            'first_seen': actor.first_seen.isoformat() if actor.first_seen else None,
            'last_seen': actor.last_seen.isoformat() if actor.last_seen else None,
            'description': actor.description,
            'motivation': actor.motivation,
            'references': actor.references
        }
    
    def _initialize_sample_actors(self):
        """Initialize with sample APT groups."""
        if self.actors:
            return  # Already loaded
        
        sample_actors = [
            ThreatActor(
                actor_id="APT28",
                name="APT28",
                aliases=["Fancy Bear", "Sofacy", "Sednit"],
                actor_type="nation-state",
                sophistication="expert",
                techniques=["T1190", "T1059", "T1078", "T1071"],
                tools=["X-Agent", "Sofacy", "Zebrocy"],
                malware=["X-Agent", "Sofacy"],
                target_industries=["Government", "Military", "Defense", "Media"],
                target_countries=["USA", "Europe", "Ukraine"],
                attributed_campaigns=["DNC Hack", "Olympic Destroyer"],
                confidence=0.9,
                first_seen=datetime(2007, 1, 1),
                last_seen=datetime.utcnow(),
                description="Russian state-sponsored APT group",
                motivation="Espionage, Information gathering",
                references=["https://attack.mitre.org/groups/G0007/"]
            ),
            ThreatActor(
                actor_id="APT29",
                name="APT29",
                aliases=["Cozy Bear", "The Dukes"],
                actor_type="nation-state",
                sophistication="expert",
                techniques=["T1190", "T1566", "T1078"],
                tools=["CozyDuke", "MiniDuke", "SeaDuke"],
                malware=["CozyDuke", "SeaDuke"],
                target_industries=["Government", "Think Tanks", "Healthcare"],
                target_countries=["USA", "Europe"],
                attributed_campaigns=["SolarWinds Supply Chain"],
                confidence=0.85,
                first_seen=datetime(2008, 1, 1),
                last_seen=datetime.utcnow(),
                description="Russian state-sponsored APT group",
                motivation="Espionage",
                references=["https://attack.mitre.org/groups/G0016/"]
            ),
            ThreatActor(
                actor_id="LAZARUS",
                name="Lazarus Group",
                aliases=["Hidden Cobra", "Guardians of Peace"],
                actor_type="nation-state",
                sophistication="advanced",
                techniques=["T1190", "T1059", "T1071"],
                tools=["WannaCry", "KEYMARBLE", "SHARPKNOT"],
                malware=["WannaCry", "KEYMARBLE"],
                target_industries=["Financial", "Cryptocurrency", "Entertainment"],
                target_countries=["USA", "South Korea", "Global"],
                attributed_campaigns=["Sony Pictures Hack", "WannaCry", "Bangladesh Bank Heist"],
                confidence=0.9,
                first_seen=datetime(2009, 1, 1),
                last_seen=datetime.utcnow(),
                description="North Korean state-sponsored APT group",
                motivation="Financial gain, Espionage, Disruption",
                references=["https://attack.mitre.org/groups/G0032/"]
            )
        ]
        
        for actor in sample_actors:
            self.actors[actor.actor_id] = actor
            self._save_actor(actor)
    
    def _load_actors(self):
        """Load threat actors from disk."""
        for actor_file in self.data_dir.glob("*.json"):
            try:
                with open(actor_file, 'r') as f:
                    data = json.load(f)
                    
                # Convert datetime strings
                if data.get('first_seen'):
                    data['first_seen'] = datetime.fromisoformat(data['first_seen'])
                if data.get('last_seen'):
                    data['last_seen'] = datetime.fromisoformat(data['last_seen'])
                
                actor = ThreatActor(**data)
                self.actors[actor.actor_id] = actor
            except Exception:
                pass
    
    def _save_actor(self, actor: ThreatActor):
        """Save threat actor to disk."""
        actor_file = self.data_dir / f"{actor.actor_id}.json"
        
        data = {
            'actor_id': actor.actor_id,
            'name': actor.name,
            'aliases': actor.aliases,
            'actor_type': actor.actor_type,
            'sophistication': actor.sophistication,
            'techniques': actor.techniques,
            'tools': actor.tools,
            'malware': actor.malware,
            'target_industries': actor.target_industries,
            'target_countries': actor.target_countries,
            'attributed_campaigns': actor.attributed_campaigns,
            'confidence': actor.confidence,
            'first_seen': actor.first_seen.isoformat() if actor.first_seen else None,
            'last_seen': actor.last_seen.isoformat() if actor.last_seen else None,
            'description': actor.description,
            'motivation': actor.motivation,
            'references': actor.references
        }
        
        try:
            with open(actor_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

