import glob
import pkgutil
import logging
import importlib

logger = logging.getLogger(__name__)

def load_plugins(subparser):
    plugins = []
    for _, name, ispkg in pkgutil.iter_modules(__path__):
        if not ispkg:
            m = importlib.import_module(__name__+'.'+name)
            logger.debug('Loaded module: '+m.PLUGIN_NAME)
            m.get_arg_parser(subparser)
            plugins.append(m)
    return plugins
