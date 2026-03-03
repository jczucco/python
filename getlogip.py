#!/usr/bin/env python3
import sys
import os
import csv
import ipaddress
from elasticsearch import Elasticsearch

# --- CONFIGURAÇÕES ---
# No ES 7.x, o host deve ser uma string completa ou um dicionário formatado
ES_HOST = os.getenv('ES_HOST', 'https://localhost:9200')
ES_USER = os.getenv('ES_USER', 'user1')
ES_PASS = os.getenv('ES_PASS', 'passXXXX')
CA_CERT = os.getenv('ES_CA_CERT', '/etc/elasticsearch/certs/ca.crt')
LIMIT_RESULTS = 10000

def get_es_client():
    try:
        # Configuração específica para a versão 7.x
        return Elasticsearch(
            [ES_HOST],
            http_auth=(ES_USER, ES_PASS), # Versão 7.x usa http_auth
            use_ssl=True,
            verify_certs=True,
            ca_certs=CA_CERT,
            timeout=30
        )
    except Exception as e:
        print(f"Erro na conexão: {e}")
        sys.exit(1)

def fetch_logs(ip_query):
    client = get_es_client()
    
    # Em 7.x, campos incluídos são passados no parâmetro _source
    source_fields = [
        "@timestamp", "source.address", "host.ip", 
        "http.request.method", "url.original", "user_agent.original"
    ]

    # A estrutura da busca deve ser passada inteira para o parâmetro 'body'
    search_body = {
        "query": {
            "match": { "source.address": ip_query }
        },
        "size": LIMIT_RESULTS,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    try:
        # Chamada explícita usando 'body' e '_source'
        response = client.search(
            index="filebeat-*", 
            body=search_body, 
            _source=source_fields
        )
        return response['hits']['hits']
    except Exception as e:
        print(f"Erro na busca: {e}")
        return []

def format_output(hits):
    writer = csv.writer(sys.stdout, delimiter='|', quoting=csv.QUOTE_MINIMAL)
    
    for hit in hits:
        src = hit.get('_source', {})
        
        def get_val(path, default="-"):
            keys = path.split('.')
            val = src
            for key in keys:
                if isinstance(val, dict):
                    val = val.get(key)
                else:
                    return default
            
            # Garante que se o campo for uma lista (comum em host.ip), pegamos o primeiro item
            if isinstance(val, list) and len(val) > 0:
                val = val[0]
            
            return str(val) if val is not None else default

        row = [
            get_val('@timestamp'),
            get_val('source.address'),
            get_val('host.ip'),
            get_val('http.request.method'),
            get_val('url.original'),
            get_val('user_agent.original')
        ]
        writer.writerow(row)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <IP_ADDRESS>")
        sys.exit(1)

    target_ip = sys.argv[1]
    
    # Validação de IP
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        print(f"Erro: '{target_ip}' não é um endereço IP válido.")
        sys.exit(1)

    results = fetch_logs(target_ip)
    if results:
        format_output(results)
    else:
        print("Nenhum registro encontrado.")
