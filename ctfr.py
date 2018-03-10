#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
------------------------------------------------------------------------------
    CTFR - 04.03.18.02.10.00 - Sheila A. Berta (UnaPibaGeek)
------------------------------------------------------------------------------
"""

## # LIBRARIES # ##
import re
import sys
import json
import socket
import requests

from berserker_resolver import Resolver

from dns.rdtypes.IN import A, AAAA

## # CONTEXT VARIABLES # ##
version = 1.2

## # MAIN FUNCTIONS # ##

def parse_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', type=str, required=True, help="Target domain.")
    parser.add_argument('-o', '--output', type=str, help="Output file.")
    parser.add_argument('-n', '--nameserver', type=str, help="Which nameserver to use")
    parser.add_argument('-r', '--resolve', action='store_true', help="Resolve domains")
    parser.add_argument('-u', '--up', action='store_true', help="Show only resolved domains")
    parser.add_argument('-j', '--json', action='store_true', help="Saves to JSON")
    return parser.parse_args()

def banner():
    global version
    b = '''
          ____ _____ _____ ____
         / ___|_   _|  ___|  _ \
        | |     | | | |_  | |_) |
        | |___  | | |  _| |  _ <
         \____| |_| |_|   |_| \_\\

     Version {v} - Hey don't miss AXFR!
    Made by Sheila A. Berta (UnaPibaGeek)
    '''.format(v=version)
    print(b, file=sys.stderr)

def clear_url(target):
    return re.sub('.*www\.','',target,1).split('/')[0].strip()

def merge(source, destination):
    """
    run me with nosetests --with-doctest file.py

    >>> a = { 'first' : { 'all_rows' : { 'pass' : 'dog', 'number' : '1' } } }
    >>> b = { 'first' : { 'all_rows' : { 'fail' : 'cat', 'number' : '5' } } }
    >>> merge(b, a) == { 'first' : { 'all_rows' : { 'pass' : 'dog', 'fail' : 'cat', 'number' : '5' } } }
    True
    """
    for key, value in source.items():
        if isinstance(value, dict):
            # get node or create one
            node = destination.setdefault(key, {})
            merge(value, node)
        else:
            destination[key] = value

    return destination

def save_subdomains(resolved, args):
    if args.json:
        try:
            with open(args.output, "r") as f:
                json_out = json.loads(f.read())
                json_out = merge(resolved, json_out)
        except:
            json_out = resolved

        with open(args.output, "w") as f:
            f.write(json.dumps(json_out, indent=2))
            f.close()
    else:
        with open(args.output, "a") as f:
            for subdomain, ips in resolved.items():
                if args.resolve:
                    f.write("{s};{i}\n".format(
                        s=subdomain, i=','.join(ips)))
                else:
                    f.write("{s}\n".format(s=subdomain))
            f.close()

def get_virustotal(domain):

    req = requests.get("https://www.virustotal.com/vtapi/v2/domain/report?apikey={api}&domain={d}".format(
        api="24f9cf9432b2f7ebc1b48eb5ea90b9633a1862a351ee813edb795d03d289249d",
        d=domain))

    if req.status_code != 200:
        print("[X] Error! Invalid domain or information not available!", file=sys.stderr)
        return []

    json_data = json.loads(req.text)

    if 'subdomains' in json_data:
        return json_data['subdomains']
    else:
        return []

def get_resolvers():
    resolvers = []
    try:
        with open( '/etc/resolv.conf', 'r' ) as resolvconf:
            for line in resolvconf.readlines():
                line = line.split( '#', 1 )[ 0 ];
                line = line.rstrip();
                if 'nameserver' in line:
                    resolvers.append( line.split()[ 1 ] )
        return resolvers
    except IOError as error:
        return ['8.8.8.8', '9.9.9.9']

def get_crt(target):
    req = requests.get("https://crt.sh/?q=%.{d}&output=json".format(d=target))

    subdomains = []

    if req.status_code != 200:
        print("[X] Error! Invalid domain or information not available!", file=sys.stderr)
        return subdomains

    json_data = json.loads('[{}]'.format(req.text.replace('}{', '},{')))

    for (key,value) in enumerate(json_data):
        subdomains.append(value['name_value'])

    return subdomains


def resolve_domains(domains, args):

    if args.nameserver:
        nameservers = [args.nameserver]
    else:
        nameservers = get_resolvers()


    resolver = Resolver(nameservers=nameservers)
    result = resolver.resolve(
        [d for d in domains if not re.search(r"\*|@", d)],
    )

    out = {}
    for d in domains:
        if d in result:
            out[d] = {
                "addresses": [ip.address for ip in result[d] if
                     isinstance(ip, (A.A, AAAA.AAAA))]
            }
        else:
            out[d] = {}

    return out

def main():
    banner()
    args = parse_args()

    subdomains = []
    target = clear_url(args.domain)
    output = args.output

    print("\n[!] ---- TARGET: {d} ---- [!] \n".format(d=target), file=sys.stderr)

    subdomains += get_crt(target)
    subdomains += get_virustotal(target)

    subdomains = sorted(set(subdomains))

    if args.resolve:
        resolved = resolve_domains(subdomains, args)
    else:
        resolved = {d: [] for d in subdomains}

    if args.up:
        # Filter domains that don't resolves
        resolved = {
            d: i for d, i in resolved.items() if len(i) > 0
        }

    for subdomain, ips in resolved.items():
        if args.up and len(ips) == 0:
            return

        if args.resolve:
            print("{s};{i}".format(
                s=subdomain, i=','.join(ips)))
        else:
            print("{s}".format(s=subdomain))

    if output is not None:
        save_subdomains(resolved, args)

    print("\n\n[!]  Done. Have a nice day! ;).", file=sys.stderr)


main()
