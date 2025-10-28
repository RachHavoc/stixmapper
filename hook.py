from app.utility.base_world import BaseWorld
from plugins.stixmapper.app.stixmapper_gui import StixmapperGUI
from plugins.stixmapper.app.stixmapper_api import StixmapperAPI

name = 'Stixmapper'
description = 'Map STIX attack-patterns to CALDERA abilities'
address = '/plugin/stixmapper/gui'
access = BaseWorld.Access.RED


async def enable(services):
    app = services.get('app_svc').application
    stixmapper_gui = StixmapperGUI(services, name=name, description=description)
    app.router.add_static('/stixmapper', 'plugins/stixmapper/static/', append_version=True)
    app.router.add_route('GET', '/plugin/stixmapper/gui', stixmapper_gui.splash)

    stixmapper_api = StixmapperAPI(services)
    # Add API routes here
    app.router.add_route('POST', '/plugin/stixmapper/mirror', stixmapper_api.mirror)
    # New STIX-to-ability matching route 
    app.router.add_route('POST', '/plugin/stixmapper/stix/match', stixmapper_api.match_stix)



