#!/usr/bin/env python3

LIMIT_RESULTS=3000

import sys,ipaddress,netaddr
from elasticsearch import Elasticsearch
from ssl import create_default_context

context = create_default_context(cafile="/etc/elasticsearch/certs/ca.crt")
client = Elasticsearch(
    ['PUT_YOUR_ELASTICSERVER_IP_HERE'],
    http_auth=('USERNAME', 'PASSWORD'),
    scheme="https",
    port=9200,
    ssl_context=context,
    timeout=30,
)

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

try:
    result = client.count(
        index="filebeat-*",
        body={
          "sort" : [ {
            "@timestamp" : {
              "order": "desc"
            }
          } ],
          "query": {
          "match": {
            "source.address": {
              "query": IP
            }
          }
        },
      }
    )
except Except:
    raise AssertionError("Error connecting to elasticsearch")
    sys.exit(2)

if ( result['count'] <= LIMIT_RESULTS ):
    num_docs=result['count']
else:
    num_docs=LIMIT_RESULTS

response = client.search(
    index="filebeat-*",
    body={
      "query": {
        "match": {
          "source.address": {
            "query": IP
          }
        }
      }, "size": num_docs
    }
)
if netaddr.valid_ipv4(IP) is True:
    for hit in response['hits']['hits']:
        try:
            print('"%s" | "%s" | "%s" | "%s" | "%s" | "%s"' % (
                hit['_source']['@timestamp'],
                hit['_source']['source']['address'],
                hit['_source']['host']['ip'][0],
                hit['_source']['http']['request']['method'],
                hit['_source']['url']['original'],
                hit['_source']['user_agent']['original']
            ))
        except KeyError:
            pass
else:
    if netaddr.valid_ipv6(IP) is True:
        for hit in response['hits']['hits']:
            try:
                print('"%s" | "%s" | "%s" | "%s" | "%s" | "%s"' % (
                    hit['_source']['@timestamp'],
                    hit['_source']['source']['address'],
                    hit['_source']['host']['ip'][1],
                    hit['_source']['http']['request']['method'],
                    hit['_source']['url']['original'],
                    hit['_source']['user_agent']['original']
                ))
            except KeyError:
                pass
    else:
        print('IP address invalid: %s' % P)
        sys.exit(2)
