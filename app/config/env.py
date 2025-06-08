import configparser

class Env:
    @staticmethod
    def load_config(file_path='settings.conf'):
        config = configparser.ConfigParser()
        config.read(file_path)

        # AD settings
        server = config.get('ad', 'server', fallback='10.19.2.7')
        bind_user = config.get('ad', 'bind_user', fallback='')
        bind_password = config.get('ad', 'bind_password', fallback='')
        search_base = config.get('ad', 'search_base', fallback='')
        user_ou = config.get('ad', 'user_ou', fallback='')
        domain = config.get('ad', 'domain', fallback='')

        # Elasticsearch
        elastic_user = config.get('elasticsearch', 'ELASTIC_SEARCH_USER', fallback='elastic')
        elastic_password = config.get('elasticsearch', 'ELASTIC_SEARCH_PASSWORD', fallback='')

        # Database
        sqlalchemy_url = config.get('database', 'SQLALCHEMY_DATABASE_URL', fallback='')

        return {
            'server': server,
            'bind_user': bind_user,
            'bind_password': bind_password,
            'search_base': search_base,
            'user_ou': user_ou,
            'domain': domain,
            'elastic_user': elastic_user,
            'elastic_password': elastic_password,
            'sqlalchemy_url': sqlalchemy_url
        }

config = Env.load_config()

# Usage
SERVER = config['server']
BIND_USER = config['bind_user']
BIND_PASSWORD = config['bind_password']
SEARCH_BASE = config['search_base']
USER_OU = config['user_ou']
DOMAIN = config['domain']

ELASTIC_SEARCH_USER = config['elastic_user']
ELASTIC_SEARCH_PASSWORD = config['elastic_password']

SQLALCHEMY_DATABASE_URL = config['sqlalchemy_url']
