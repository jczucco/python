import sys,ipaddress
from elasticsearch import Elasticsearch
client = Elasticsearch()

#IP=ipaddress.ip_address(argv[1])
try:
    IP = ipaddress.ip_address(sys.argv[1])
    #print("Getting logs of IP |",IP,"|")
    IP=sys.argv[1]
except ValueError:
    print('IP address invalid: %s' % sys.argv[1])
    sys.exit(2)
except:
    print('Usage : %s  <IP ADDRESS>' % sys.argv[0])
    sys.exit(2)

response = client.search(
    index="filebeat-*",
    body={
      "query": {
        "match": {
          "nginx.access.remote_ip": {
            "query": IP
          } 
        } 
      }, "size": 100
    } 
)

for hit in response['hits']['hits']:
    print('"%s" | "%s" | "%s" | "%s" | "%s"' % (
        hit['_source']['@timestamp'],
        hit['_source']['nginx']['access']['remote_ip'],
        hit['_source']['nginx']['access']['method'],
        hit['_source']['nginx']['access']['url'],
        hit['_source']['nginx']['access']['user_agent']['original']
        ))
