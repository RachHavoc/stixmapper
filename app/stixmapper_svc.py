import logging
import re
from typing import Dict, List, Set, Tuple

class StixmapperService:
    def __init__(self, services):
        self.services = services
        self.file_svc = services.get('file_svc')
        self.log = logging.getLogger('stixmapper_svc')

    async def foo(self):
        return 'bar'

    # Add functions here that call core services
    async def match_stix_to_abilities(self, stix_bundle: dict, fallback_to_parent: bool = True, filter_by_tactic: bool = False) -> dict:
        """
        Given a STIX bundle, extract ATT&CK technique IDs and match them to CALDERA abilities.
        - fallback_to_parent: if True, when STIX has a sub-technique T####.### but no exact matches exist,
            try matching parent T#### abilities.
        - filter_by_tactic: if True, only include abilities whose tactic matches one of the
            technique's kill_chain_phases.
        """
        technique_to_tactics, techniques_found = self._extract_techniques_from_stix(stix_bundle)
        abilities = await self._get_all_abilities()

        # Build indexes for fast lookups
        abilities_by_technique = {}
        for ab in abilities:
            tid = (getattr(ab, 'technique_id', None) or '').upper()
            if not tid:
                continue
            abilities_by_technique.setdefault(tid, []).append(ab)

        matches = []
        unmatched = []

        for technique_id in sorted(techniques_found):
            wanted_tactics = technique_to_tactics.get(technique_id, set())
            # Exact match first
            matched_list = list(abilities_by_technique.get(technique_id, []))

            # Optional: filter abilities by tactic to match STIX kill chain phases
            if filter_by_tactic and matched_list and wanted_tactics:
                matched_list = [ab for ab in matched_list if getattr(ab, 'tactic', None) in wanted_tactics]

            # Fallback to parent if requested and no matches yet
            if not matched_list and fallback_to_parent and '.' in technique_id:
                parent_id = technique_id.split('.')[0]
                parent_matches = list(abilities_by_technique.get(parent_id, []))
                if filter_by_tactic and parent_matches and wanted_tactics:
                    parent_matches = [ab for ab in parent_matches if getattr(ab, 'tactic', None) in wanted_tactics]
                matched_list = parent_matches

            if matched_list:
                matches.append({
                    'technique_id': technique_id,
                    'tactics': sorted(list(wanted_tactics)),
                    'abilities': [self._ability_to_dict(ab) for ab in matched_list]
                })
            else:
                unmatched.append(technique_id)

        return {
            'techniques_total': len(techniques_found),
            'matches_total': len(matches),
            'unmatched_total': len(unmatched),
            'matches': matches,
            'unmatched': unmatched
        }

    def _extract_techniques_from_stix(self, stix_bundle: dict) -> Tuple[Dict[str, Set[str]], Set[str]]:
        """
        Returns:
            - mapping technique_id -> set of tactics (kill chain phase names), lower-case
            - set of technique_ids
        We focus on 'attack-pattern' objects and pull technique IDs from external_references.external_id fields
        that look like T#### or T####.###. We also capture kill_chain_phases.phase_name as tactics.
        """
        technique_to_tactics: Dict[str, Set[str]] = {}
        techniques_found: Set[str] = set()

        objects = stix_bundle.get('objects') or []
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            if obj.get('type') != 'attack-pattern':
                continue

            tactic_names = set()
            for kcp in obj.get('kill_chain_phases', []) or []:
                # Commonly kill_chain_name: 'mitre-attack', phase_name: 'defense-evasion', etc.
                phase = (kcp.get('phase_name') or '').strip().lower()
                if phase:
                    tactic_names.add(phase)

            # Collect technique IDs from external_references
            for ref in obj.get('external_references', []) or []:
                ext_id = (ref.get('external_id') or '').strip()
                # Accept T#### or T####.### case-insensitively
                if ext_id and re.match(r'(?i)^T\d{4}(\.\d{3})?$', ext_id):
                    tid = ext_id.upper()
                    techniques_found.add(tid)
                    if tactic_names:
                        technique_to_tactics.setdefault(tid, set()).update(tactic_names)

        return technique_to_tactics, techniques_found

    async def _get_all_abilities(self):
        """
        Return all abilities from CALDERA's data service.
        """
        # In CALDERA, data_svc.locate('abilities', match_dict) returns a list of Ability objects
        return await self.data_svc.locate('abilities', match=dict())

    def _ability_to_dict(self, ab) -> dict:
        """
        Convert an Ability object to a minimal serializable dict for the UI.
        """
        platforms = []
        try:
            # ability.platforms is typically a dict of platform->executors
            if hasattr(ab, 'platforms') and isinstance(ab.platforms, dict):
                platforms = list(ab.platforms.keys())
        except Exception:
            platforms = []

        return {
            'ability_id': getattr(ab, 'ability_id', None),
            'name': getattr(ab, 'name', None),
            'description': getattr(ab, 'description', None),
            'tactic': getattr(ab, 'tactic', None),
            'technique_id': getattr(ab, 'technique_id', None),
            'technique_name': getattr(ab, 'technique_name', None),
            'plugin': getattr(ab, 'plugin', None),
            'platforms': platforms
        }