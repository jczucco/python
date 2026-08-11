#!/usr/bin/env python3
import sys
import ipaddress
import re
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, ASNLookupError

# Regex rigorosa para validação do formato de e-mail
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

# Regex para busca em texto bruto (Fallback)
RAW_EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

def sanitize_and_validate_email(email_str):
    """Remove caracteres indesejados nas pontas e valida o formato do e-mail."""
    if not email_str or not isinstance(email_str, str):
        return None
    
    # Sanitização: Remove espaços em branco e pontos residuais no final do e-mail
    cleaned = email_str.strip().rstrip('.')
    
    # Validação
    if re.match(EMAIL_REGEX, cleaned):
        return cleaned.lower()
    return None

def extract_emails_recursively(entity_data):
    """Percorre recursivamente as entidades, tratando se forem lista ou dicionário."""
    emails = set()
    
    if isinstance(entity_data, list):
        items = entity_data
    elif isinstance(entity_data, dict):
        items = entity_data.values()
    else:
        return emails

    for entity in items:
        if not isinstance(entity, dict):
            continue

        # 1. Tenta pegar do vcard (formato padrão RDAP)
        vcard = entity.get('vcard', [])
        for entry in vcard:
            if isinstance(entry, list) and len(entry) > 3 and entry[0] == 'email':
                valid_email = sanitize_and_validate_email(entry[3])
                if valid_email:
                    emails.add(valid_email)

        # 2. Tenta pegar do campo 'emails' direto
        direct_emails = entity.get('emails', [])
        if isinstance(direct_emails, list):
            for e in direct_emails:
                valid_email = sanitize_and_validate_email(e)
                if valid_email:
                    emails.add(valid_email)
        elif isinstance(direct_emails, str):
            valid_email = sanitize_and_validate_email(direct_emails)
            if valid_email:
                emails.add(valid_email)

        # 3. Mergulha nas sub-entidades (Recursividade)
        if 'entities' in entity:
            emails.update(extract_emails_recursively(entity['entities']))
            
    return emails

def get_ip_contacts(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        
        print(f"[*] Analisando IP: {ip_str}...")
        obj = IPWhois(ip_str)
        results = obj.lookup_rdap(depth=3)
        
        found_emails = extract_emails_recursively(results.get('entities', {}))
        
        # Fallback: Se não achou nada no RDAP, tenta busca bruta no texto do objeto
        if not found_emails:
            raw_text = str(results)
            matches = re.findall(RAW_EMAIL_REGEX, raw_text)
            for raw_e in matches:
                valid_email = sanitize_and_validate_email(raw_e)
                if valid_email:
                    found_emails.add(valid_email)

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
            print(f"[+] {email}")
    else:
        print("[-] Nenhum e-mail encontrado.")
