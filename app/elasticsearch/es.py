from elasticsearch8 import Elasticsearch
es: Elasticsearch = Elasticsearch("https://es01:9200", basic_auth=("elastic", "kibana123"), verify_certs=False)
