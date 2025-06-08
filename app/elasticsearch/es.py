from elasticsearch8 import Elasticsearch
from app.config import env
es: Elasticsearch = Elasticsearch("https://es01:9200", basic_auth=(env.ELASTIC_SEARCH_USER, env.ELASTIC_SEARCH_PASSWORD), verify_certs=False)
