import re
import logging
from typing import Dict, List, Optional, Set, Any

MITRE_TECH_ID_RE = re.compile(r"^(?P<tech>T\d{4})(?:\.(?P<sub>\d{3}))?$", re.IGNORECASE)
MITRE_URL_ID_RE = re.compile(r"/techniques/(?P<tech_id>T\d{4})(?:/(?P<sub>\d{3}))?", re.IGNORECASE)


class StixmapperService:
    def __init__(self, services):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.log = (
            services.get('app_svc').log
            if services.get('app_svc')
            else logging.getLogger('stixmapper_svc')
        )

    async def match_stix_to_abilities(
        self,
        stix_bundle: Dict,
        fallback_to_parent: bool = True,
        filter_by_tactic: bool = False
    ) -> Dict:
        if not isinstance(stix_bundle, dict) or stix_bundle.get('type') != 'bundle':
            raise ValueError("Expected a STIX bundle object with type='bundle'")

        objs = stix_bundle.get('objects') or []
        attack_patterns = [
            o for o in objs
            if isinstance(o, dict) and o.get('type') == 'attack-pattern'
        ]

        mappings: List[Dict] = []
        ap_with_tech = 0
        total_abilities = 0

        for ap in attack_patterns:
            ap_id = ap.get('id')
            ap_name = ap.get('name')
            tactics = self._extract_mitre_tactics(ap)
            technique_id = self._extract_mitre_technique_id(ap)

            abilities: List[Dict] = []
            parent_technique_id = None

            if technique_id:
                ap_with_tech += 1
                abilities = await self._find_abilities_for_attack_id(technique_id)

                if not abilities and fallback_to_parent and '.' in technique_id:
                    parent_technique_id = technique_id.split('.', 1)[0].upper()
                    abilities = await self._find_abilities_for_attack_id(parent_technique_id)

                if filter_by_tactic and tactics and abilities:
                    tactic_set = set(tactics)
                    abilities = [a for a in abilities if a.get('tactic') in tactic_set]

                total_abilities += len(abilities)

            mappings.append({
                "attack_pattern_id": ap_id,
                "name": ap_name,
                "technique_id": technique_id,
                **({"parent_technique_id": parent_technique_id} if parent_technique_id else {}),
                "tactics": tactics,
                "abilities": abilities
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
        refs = ap.get("external_references") or []

        for ref in refs:
            if (ref.get("source_name") or "").lower() == "mitre-attack":
                ext_id = (ref.get("external_id") or "").strip()
                if ext_id and MITRE_TECH_ID_RE.match(ext_id):
                    return ext_id.upper()

                url = ref.get("url") or ""
                m = MITRE_URL_ID_RE.search(url)
                if m:
                    tech = m.group("tech_id").upper()
                    sub = m.group("sub")
                    return f"{tech}.{sub}" if sub else tech

        for ref in refs:
            url = ref.get("url") or ""
            m = MITRE_URL_ID_RE.search(url)
            if m:
                tech = m.group("tech_id").upper()
                sub = m.group("sub")
                return f"{tech}.{sub}" if sub else tech

        return None

    def _extract_mitre_tactics(self, ap: Dict) -> List[str]:
        phases = ap.get("kill_chain_phases") or []
        tactics: Set[str] = set()
        for p in phases:
            if (p.get("kill_chain_name") or "").lower() == "mitre-attack":
                ph = (p.get("phase_name") or "").strip()
                if ph:
                    tactics.add(ph)
        return sorted(tactics)

    async def _find_abilities_for_attack_id(self, attack_id: str) -> List[Dict]:
        all_abilities = await self.data_svc.locate('abilities', match=dict())

        matched: List[Dict] = []
        for a in all_abilities or []:
            tech = self._get(a, ["technique"]) or {}
            ability_attack_id = (
                tech.get("attack_id") if isinstance(tech, dict)
                else getattr(tech, "attack_id", None)
            )
            tech_name = (
                tech.get("name") if isinstance(tech, dict)
                else getattr(tech, "name", None)
            )

            if (ability_attack_id or "").upper() == attack_id.upper():
                matched.append({
                    "ability_id": self._get(a, ["ability_id"]) or self._get(a, ["id"]),
                    "name": self._get(a, ["name"]),
                    "tactic": self._get(a, ["tactic"]),
                    "technique": {
                        "attack_id": ability_attack_id,
                        "name": tech_name
                    }
                })

        return matched

    def _get(self, obj: Any, path: List[str], default: Any = None) -> Any:
        cur: Any = obj
        for key in path:
            cur = cur.get(key) if isinstance(cur, dict) else getattr(cur, key, None)
            if cur is None:
                return default
        return cur
