import re
from typing import Dict, List, Optional, Set, Any

MITRE_TECH_ID_RE = re.compile(r"^(?P<tech>T\d{4})(?:\.(?P<sub>\d{3}))?$", re.IGNORECASE)
MITRE_URL_ID_RE = re.compile(r"/techniques/(?P<tech_id>T\d{4})(?:/(?P<sub>\d{3}))?", re.IGNORECASE)

class StixmapperService:
    def __init__(self, services):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.log = services.get('app_svc').log if services.get('app_svc') else None

    async def match_stix_to_abilities(self, stix_bundle: Dict,
                                      fallback_to_parent: bool = True,
                                      filter_by_tactic: bool = False) -> Dict:
        """
        Map STIX 2.x attack-patterns to CALDERA abilities.
        Supports spec_version 2.0 and 2.1.
        Extracts MITRE technique/sub-technique IDs (e.g., T1055.011) from external_references.
        Matches abilities by technique.attack_id. Falls back to parent technique if requested.
        Optionally filters by tactics present in kill_chain_phases (kill_chain_name == 'mitre-attack').
        """
        if not isinstance(stix_bundle, dict) or stix_bundle.get('type') != 'bundle':
            raise ValueError("Expected a STIX bundle object with type='bundle'")

        objs = stix_bundle.get('objects') or []
        attack_patterns = [o for o in objs if o.get('type') == 'attack-pattern']

        mappings: List[Dict] = []
        ap_with_tech = 0
        total_abilities = 0

        for ap in attack_patterns:
            ap_id = ap.get('id')
            ap_name = ap.get('name')
            tactics = self._extract_mitre_tactics(ap)
            technique_id = self._extract_mitre_technique_id(ap)

            if technique_id:
                ap_with_tech += 1
                abilities = await self._find_abilities_for_attack_id(technique_id)

                parent_technique_id = None
                if not abilities and fallback_to_parent and '.' in technique_id:
                    parent_technique_id = technique_id.split('.', 1)[0].upper()
                    abilities = await self._find_abilities_for_attack_id(parent_technique_id)

                if filter_by_tactic and tactics and abilities:
                    tactic_set = set(tactics)
                    abilities = [a for a in abilities if (a.get('tactic') in tactic_set)]

                total_abilities += len(abilities)

                mappings.append({
                    "attack_pattern_id": ap_id,
                    "name": ap_name,
                    "technique_id": technique_id,
                    **({"parent_technique_id": parent_technique_id} if parent_technique_id else {}),
                    "tactics": tactics,
                    "abilities": abilities
                })
            else:
                mappings.append({
                    "attack_pattern_id": ap_id,
                    "name": ap_name,
                    "technique_id": None,
                    "tactics": tactics,
                    "abilities": []
                })

        return {
            "mappings": mappings,
            "stats": {
                "attack_patterns": len(attack_patterns),
                "with_technique": ap_with_tech,
                "abilities_found": total_abilities
            }
        }

    def _extract_mitre_technique_id(self, ap: Dict) -> Optional[str]:
        """
        Extract Txxxx or Txxxx.xxx from external_references with source_name 'mitre-attack',
        or parse it from ATT&CK URLs like https://attack.mitre.org/techniques/T1055/011.
        Returns uppercase technique ID or None.
        """
        refs = ap.get("external_references") or []

        # Prefer source_name == 'mitre-attack'
        for ref in refs:
            if (ref.get("source_name") or "").lower() == "mitre-attack":
                ext_id = (ref.get("external_id") or "").strip()
                if ext_id:
                    m = MITRE_TECH_ID_RE.match(ext_id)
                    if m:
                        return m.group(0).upper()
                url = ref.get("url") or ""
                m = MITRE_URL_ID_RE.search(url)
                if m:
                    tech = m.group("tech_id").upper()
                    sub = m.group("sub")
                    return f"{tech}.{sub}" if sub else tech

        # Fallback: any URL that contains /techniques/Txxxx(/xxx)
        for ref in refs:
            url = ref.get("url") or ""
            m = MITRE_URL_ID_RE.search(url)
            if m:
                tech = m.group("tech_id").upper()
                sub = m.group("sub")
                return f"{tech}.{sub}" if sub else tech

        return None

    def _extract_mitre_tactics(self, ap: Dict) -> List[str]:
        """
        Return tactic phase_names for kill_chain_name == 'mitre-attack'.
        Example: ['defense-evasion','privilege-escalation'].
        """
        phases = ap.get("kill_chain_phases") or []
        tactics: Set[str] = set()
        for p in phases:
            if (p.get("kill_chain_name") or "").lower() == "mitre-attack":
                ph = (p.get("phase_name") or "").strip()
                if ph:
                    tactics.add(ph)
        return sorted(tactics)

    async def _find_abilities_for_attack_id(self, attack_id: str) -> List[Dict]:
        """
        Locate abilities whose technique.attack_id equals attack_id (e.g., 'T1055' or 'T1055.011').
        Normalizes output fields: ability_id, name, tactic, technique.attack_id, technique.name.
        """
        # Fetch all abilities and filter in Python to handle nested fields robustly
        all_abilities = await self.data_svc.locate('abilities')

        matched: List[Dict] = []
        for a in all_abilities or []:
            # Handle both dict and object ability representations
            tech = self._get(a, ["technique"]) or {}
            ability_attack_id = None
            if isinstance(tech, dict):
                ability_attack_id = tech.get("attack_id")
                tech_name = tech.get("name")
            else:
                ability_attack_id = getattr(tech, "attack_id", None)
                tech_name = getattr(tech, "name", None)

            if (ability_attack_id or "").upper() == attack_id.upper():
                aid = self._get(a, ["ability_id"]) or self._get(a, ["id"]) or getattr(a, "ability_id", None) or getattr(a, "id", None)
                matched.append({
                    "ability_id": aid,
                    "name": self._get(a, ["name"]) or getattr(a, "name", None),
                    "tactic": self._get(a, ["tactic"]) or getattr(a, "tactic", None),
                    "technique": {
                        "attack_id": ability_attack_id,
                        "name": tech_name
                    }
                })

        return matched

    def _get(self, obj: Any, path: List[str], default: Any = None) -> Any:
        """
        Safely get nested keys from dicts; falls back to attributes if dict access fails.
        """
        cur: Any = obj
        for key in path:
            if isinstance(cur, dict):
                cur = cur.get(key)
            else:
                cur = getattr(cur, key, None)
            if cur is None:
                return default
        return cur