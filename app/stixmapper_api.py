import json
from aiohttp import web

from app.service.auth_svc import for_all_public_methods, check_authorization
from plugins.stixmapper.app.stixmapper_svc import StixmapperService



@for_all_public_methods(check_authorization)
class StixmapperAPI:

    def __init__(self, services):
        self.services = services
        self.auth_svc = self.services.get('auth_svc')
        self.data_svc = self.services.get('data_svc')
        self.stixmapper_svc = StixmapperService(services)

    async def mirror(self, request):
        """
        This sample endpoint mirrors the request body in its response
        """
        request_body = json.loads(await request.read())
        return web.json_response(request_body)
    
    async def match_stix(self, request):
        """
        Accepts a STIX 2.x bundle and returns a mapping of ATT&CK techniques to CALDERA abilities.
        Supports:
            - JSON: { "stix": <bundle>, "options": { "fallback_to_parent": true, "filter_by_tactic": false } }
            - multipart/form-data with a 'file' field containing JSON
        """
        try:
            stix_bundle = None
            options = {
                'fallback_to_parent': True,
                'filter_by_tactic': False
            }

            if request.content_type and request.content_type.startswith('multipart/'):
                reader = await request.multipart()
                async for part in reader:
                    if part.name == 'file':
                        raw_text = await part.text()
                        stix_bundle = json.loads(raw_text)
            else:
                body = json.loads(await request.read() or "{}")
                if isinstance(body, dict):
                    if 'options' in body and isinstance(body['options'], dict):
                        options.update(body['options'])
                    if 'stix' in body and isinstance(body['stix'], dict):
                        stix_bundle = body['stix']
                    else:
                        # Allow sending the bundle at the top-level
                        if 'type' in body and body.get('type') == 'bundle':
                            stix_bundle = body

            if not stix_bundle or not isinstance(stix_bundle, dict) or stix_bundle.get('type') != 'bundle':
                return web.json_response(
                    {'status': 'error', 'error': 'Invalid request. Provide a STIX 2.x bundle.'},
                    status=400
                )

            results = await self.stixmapper_svc.match_stix_to_abilities(
                stix_bundle=stix_bundle,
                fallback_to_parent=options.get('fallback_to_parent', True),
                filter_by_tactic=options.get('filter_by_tactic', False)
            )
            return web.json_response({'status': 'success', **results})
        except json.JSONDecodeError:
            return web.json_response({'status': 'error', 'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            # Log server-side; return generic error client-side
            return web.json_response({'status': 'error', 'error': str(e)}, status=500)
