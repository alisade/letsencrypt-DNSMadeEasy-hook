#!/usr/bin/env python3
# dnsmadeeasy hook for letsencrypt.sh
# http://www.dnsmadeeasy.com/integration/pdf/API-Docv2.pdf

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from builtins import str

from future import standard_library
standard_library.install_aliases()

import dns.exception
import dns.resolver
import logging
import os
import requests
import sys
import time

from email.utils import formatdate
from datetime import datetime
from time import mktime
import hashlib, hmac

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

# Calculate RFC 1123 HTTP/1.1 date
now = datetime.now()
stamp = mktime(now.timetuple())
requestDate =  formatdate(
    timeval     = stamp,
    localtime   = False,
    usegmt      = True
)

try:
    DME_HEADERS = {
        'x-dnsme-apiKey': os.environ['DME_API_KEY'],
        'x-dnsme-hmac': hmac.new(os.environ['DME_SECRET_KEY'].encode('ascii'), requestDate.encode('ascii'), hashlib.sha1).hexdigest(),
        'x-dnsme-requestDate': requestDate,
        'Content-Type': 'application/json',
    }
except KeyError:
    logger.error(" + Unable to locate dnsmadeeasy credentials in environment!")
    sys.exit(1)

DME_API_BASE_URL = {
    'production': 'https://api.dnsmadeeasy.com/V2.0/dns/managed',
    'staging': 'http://api.sandbox.dnsmadeeasy.com/V2.0/dns/managed'
}

try:
    dns_servers = os.environ['QUERY_DNS_SERVERS']
    dns_servers = dns_servers.split()
except KeyError:
    dns_servers = False

def _has_dns_propagated(name, token):
    txt_records = []
    try:
        if dns_servers:
            custom_resolver = dns.resolver.Resolver()
            custom_resolver.nameservers = dns_servers
            dns_response = custom_resolver.query(name, 'TXT')
        else:
            dns_response = dns.resolver.query(name, 'TXT')
        for rdata in dns_response:
            for txt_record in rdata.strings:
                txt_records.append(txt_record)
    except dns.exception.DNSException as error:
        return False

    for txt_record in txt_records:
        txt_record=txt_record.decode()
        if txt_record == token:
            return True

    return False

# http://api.dnsmadeeasy.com/V2.0/dns/managed/id/{domainname}
def _get_zone_id(domain):
    # allow both tlds and subdomains hosted on DNSMadeEasy
    tld = domain[domain.find('.')+1:]
    url = DME_API_BASE_URL['production'] + "/id/{0}".format(tld)
    r = requests.get(url, headers=DME_HEADERS)
    r.raise_for_status()
    return r.json()['id']


# http://api.dnsmadeeasy.com/V2.0/dns/managed/{domain_id}}/records?type=TXT&recordName={name}
def _get_txt_record_id(zone_id, name):
    url = DME_API_BASE_URL['production'] + "/{0}/records?type=TXT&recordName={1}".format(zone_id, name)
    r = requests.get(url, headers=DME_HEADERS)
    r.raise_for_status()
    try:
        record_id = r.json()['data'][0]['id']
    except IndexError:
        logger.info(" + Unable to locate record named {0}".format(name))
        return

    return record_id


# http://api.dnsmadeeasy.com/V2.0/dns/managed/{domain_id}}/records
def create_txt_record(args):
    domain, token = args[0], args[2]
    zone_id = _get_zone_id(domain)
    name = "{0}.{1}".format('_acme-challenge', domain)
    short_name = "{0}.{1}".format('_acme-challenge', domain[0:domain.find('.')])
    url = DME_API_BASE_URL['production'] + "/{0}/records".format(zone_id)
    payload = {
        'type': 'TXT',
        'name': short_name,
        'value': token,
        'ttl': 5,
    }
    r = requests.post(url, headers=DME_HEADERS, json=payload)
    r.raise_for_status()
    record_id = r.json()['id']
    logger.debug("+ TXT record created, ID: {0}".format(record_id))

    # give it 10 seconds to settle down and avoid nxdomain caching
    logger.info(" + Settling down for 10s...")
    time.sleep(10)

    retries=2
    while(_has_dns_propagated(name, token) == False and retries > 0):
        logger.info(" + DNS not propagated, waiting 30s...")
        retries-=1
        time.sleep(30)

    if retries <= 0:
        logger.error("Error resolving TXT record in domain {0}".format(domain))
        sys.exit(1)

# http://api.dnsmadeeasy.com/V2.0/dns/managed/{domain_id}}/records
def delete_txt_record(args):
    domain, token = args[0], args[2]
    if not domain:
        logger.info(" + http_request() error in letsencrypt.sh?")
        return

    zone_id = _get_zone_id(domain)
    name = "{0}.{1}".format('_acme-challenge', domain)
    short_name = "{0}.{1}".format('_acme-challenge', domain[0:domain.find('.')])
    record_id = _get_txt_record_id(zone_id, short_name)

    logger.debug(" + Deleting TXT record name: {0}".format(name))
    url = DME_API_BASE_URL['production'] + "/{0}/records/{1}".format(zone_id, record_id)
    r = requests.delete(url, headers=DME_HEADERS)
    r.raise_for_status()


def deploy_cert(args):
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem, timestamp = args
    logger.info(' + ssl_certificate: {0}'.format(fullchain_pem))
    logger.info(' + ssl_certificate_key: {0}'.format(privkey_pem))
    return

def unchanged_cert(args):
    return

def main(argv):
    ops = {
        'deploy_challenge': create_txt_record,
        'clean_challenge' : delete_txt_record,
        'deploy_cert'     : deploy_cert,
        'unchanged_cert'  : unchanged_cert,
    }
    logger.info(" + dnsmadeeasy hook executing: {0}".format(argv[0]))
    ops[argv[0]](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
