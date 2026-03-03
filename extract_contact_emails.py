#!/usr/bin/env python3
import sys
import ipaddress
import re
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, ASNLookupError

# Regex para validação de e-mail (mais segura)
EMAIL_REGEX = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'

def extract_emails_recursively(entity_data):
    """Percorre recursivamente as entidades, tratando se forem lista ou dicionário."""
    emails = set()
    
    # Se for uma lista, iteramos pelos itens
    if isinstance(entity_data, list):
        items = entity_data
    # Se for um dicionário, iteramos pelos valores
    elif isinstance(entity_data, dict):
        items = entity_data.values()
    else:
        return emails

    for entity in items:
        # Se for apenas uma string (ID da entidade), ignoramos e seguimos
        if not isinstance(entity, dict):
            continue

        # 1. Tenta pegar do vcard (formato padrão RDAP)
        vcard = entity.get('vcard', [])
        for entry in vcard:
            # entry costuma ser ['email', {}, 'text', 'email@addr.com']
            if isinstance(entry, list) and entry[0] == 'email':
                emails.add(entry[3].lower())

        # 2. Tenta pegar do campo 'emails' direto (alguns RIRs facilitam isso)
        direct_emails = entity.get('emails', [])
        if isinstance(direct_emails, list):
            for e in direct_emails:
                emails.add(e.lower())
        elif isinstance(direct_emails, str):
            emails.add(direct_emails.lower())

        # 3. Mergulha nas sub-entidades (Recursividade)
        if 'entities' in entity:
            emails.update(extract_emails_recursively(entity['entities']))
            
    return emails

def get_ip_contacts(ip_str):
    try:
        # Validação do IP
        ipaddress.ip_address(ip_str)
        
        print(f"[*] Analisando IP: {ip_str}...")
        obj = IPWhois(ip_str)
        
        # Consulta RDAP (mais moderno e estruturado que o WHOIS)
        # O parâmetro depth controla o quão profundo ele vai nas entidades
        results = obj.lookup_rdap(depth=3)
        
        found_emails = extract_emails_recursively(results.get('entities', {}))
        
        # Fallback: Se não achou nada no RDAP, tenta busca bruta no texto do objeto
        if not found_emails:
            raw_text = str(results)
            found_emails.update(re.findall(EMAIL_REGEX, raw_text))

        return sorted(list(found_emails))

    except IPDefinedError:
        return ["Erro: IP privado ou reservado."]
    except ASNLookupError:
        return ["Erro: Não foi possível localizar o ASN deste IP."]
    except Exception as e:
        return [f"Erro inesperado: {str(e)}"]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <IP_ADDRESS>")
        sys.exit(1)

    ip_input = sys.argv[1]
    contacts = get_ip_contacts(ip_input)

    if contacts:
        print("\n--- Contatos Encontrados ---")
        for email in contacts:
            # Filtro simples para remover e-mails genéricos ou falsos se necessário
            print(f"[+] {email}")
    else:
        print("[-] Nenhum e-mail encontrado.")
