import logging
from aiohttp_jinja2 import template

from app.service.auth_svc import for_all_public_methods, check_authorization
from app.utility.base_gui import BaseGUI


@for_all_public_methods(check_authorization)
class StixmapperGUI(BaseGUI):

    def __init__(self, services, name, description):
        super().__init__(services, name, description)
        self.log = logging.getLogger('stixmapper_gui')

    @template('stixmapper.html')
    async def splash(self, request):
        return {
            'name': self.name,
            'description': self.description
        }
