import json
import logging
from aiohttp import web

from app.service.auth_svc import for_all_public_methods, check_authorization
from plugins.stixmapper.app.stixmapper_svc import StixmapperService


@for_all_public_methods(check_authorization)
class StixmapperAPI:

    def __init__(self, services):
        self.services = services
        self.auth_svc = services.get('auth_svc')
        self.data_svc = services.get('data_svc')
        self.stixmapper_svc = StixmapperService(services)
        self.log = logging.getLogger('stixmapper_api')

    async def mirror(self, request):
        raw = await request.read()
        body = json.loads(raw.decode('utf-8')) if raw else {}
        return web.json_response(body)

    async def match_stix(self, request):
        """
        Accepts a STIX 2.x bundle and returns a mapping of ATT&CK techniques to CALDERA abilities.
        Supports:
          - multipart/form-data (file, stix, bundle, upload)
          - raw JSON body
        """
        try:
            stix_bundle = None
            options = {
                'fallback_to_parent': True,
                'filter_by_tactic': False
            }

            # ---- multipart/form-data ----
            if request.content_type and request.content_type.startswith('multipart/'):
                reader = await request.multipart()
                async for part in reader:
                    if part.name in ('file', 'stix', 'bundle', 'upload'):
                        raw = await part.read()
                        stix_bundle = json.loads(raw.decode('utf-8'))
                    elif part.name == 'options':
                        raw = await part.read()
                        options.update(json.loads(raw.decode('utf-8')))

            # ---- application/json ----
            else:
                raw = await request.read()
                if raw:
                    body = json.loads(raw.decode('utf-8'))
                    if isinstance(body, dict):
                        options.update(body.get('options', {}))
                        stix_bundle = body.get('stix') or body

            # ---- validation ----
            if not isinstance(stix_bundle, dict) or stix_bundle.get('type') != 'bundle':
                return web.json_response(
                    {'status': 'error', 'error': 'Invalid STIX bundle'},
                    status=400
                )

            results = await self.stixmapper_svc.match_stix_to_abilities(
                stix_bundle=stix_bundle,
                fallback_to_parent=options.get('fallback_to_parent', True),
                filter_by_tactic=options.get('filter_by_tactic', False)
            )

            return web.json_response({'status': 'success', 'data': results})

        except json.JSONDecodeError:
            return web.json_response(
                {'status': 'error', 'error': 'Invalid JSON'},
                status=400
            )

        except Exception:
            self.log.exception('STIX mapping failed')
            return web.json_response(
                {'status': 'error', 'error': 'STIX processing failed'},
                status=500
            )
