#!/home/scripts/ticket_automatisierung/bin/python3
import datetime
import logging
from pathlib import Path

from elasticsearch import Elasticsearch
import json
from elasticsearch import RequestsHttpConnection

import secrets

user=secrets.sc_u
pw=secrets.sc_pw
host='sn1hot03.ad001.siemens.net'
port='9200'

def main(path,sag_systems,hit_json):
    #print matched iterating: lista["i_f","vuser","wuser123","a_123","App_123"]
    es = Elasticsearch([host], port=port, connection_class=RequestsHttpConnection,
                       http_auth=(user, pw), use_ssl=True, verify_certs=False, timeout=120, retry_on_timeout=True, max_retries=3)

    dtn=datetime.datetime.now()
    lt_date = datetime.datetime(day=dtn.day, year=dtn.year, month=dtn.month)
    duration1 = datetime.timedelta(days=90)
    gte_date = lt_date - duration1

    gte_date = gte_date.strftime("%Y-%m-%dT%H:%M:%S")

    systems_ips = sag_systems

    divisor = 1000

    slices = to_slices(divisor, systems_ips)

    with open('query.json') as json_file:
        query = json.load(json_file)

    slices_index = 0
    for s in slices:
        query['bool']['filter'][0]['terms']['source.ip'] = s
        with open('query%d.json' % (slices_index + 1), 'w') as outfile:
            json.dump(query, outfile)

        for i in range(4):
            download_index(es=es,query=query,index="business_partner_00%d" % (i+1),nth=(i+1),sort="_doc",hit_json=hit_json,gte_date=gte_date,slices_index=slices_index,path=path)
        slices_index=slices_index+1
    print("Done!")


def to_slices(divisor, systems_ips):
    length = len(systems_ips)
    quotient, rest = divmod(length, divisor)
    slices = []  # [[list[0],...list[999]],]
    lower_bound = 0
    for i in range(quotient + 1):
        upper_bound = (i + 1) * divisor
        if upper_bound < length:
            slices.append(systems_ips[slice(lower_bound, upper_bound, 1)])
        else:
            slices.append(systems_ips[slice(lower_bound, length, 1)])
        lower_bound = upper_bound
    return slices


def download_index(es,query, index, nth, sort,hit_json, gte_date,slices_index,path):
    search_after = None
    seq = 0
    hits_len = 10000
    while hits_len >= 10000:
        resp = es.search(index=index,size=10000,sort=sort,search_after=search_after)
        hits = resp['hits']['hits']
        hits_len = len(resp['hits']['hits'])
        print("Got %d Hits:" % hits_len)

        filepath = path / (hit_json % (slices_index, gte_date, nth, seq))
        if hits_len==0:
            print("Not creating "+filepath.name)
        else:
            with filepath.open('w') as outfile:
                for b in hits:
                    json.dump(flattenhit(b), outfile)
                    outfile.write("\n")
        seq = seq + 1

        search_after=resp['hits']['hits'][-1]['sort']

def flattenhit(h):
    try:
        s=h['_source']['source']['ip']
        d=h['_source']['destination']['ip']
        return {"source_ip":s,"dest_ip":d}
    except KeyError as e:
        print("KeyError in flattenhit: %s\t%s" % (h["_index"],h["_id"] + " Trying to access key which is not in the dictionary"))
        return None

if __name__ == '__main__':
    main(Path("hits/"))

