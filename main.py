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

hit_json='hit_energy_00%d_%s_%d_%d.json'

def main(path,sag_systems):
    #print matched iterating: lista["i_f","vuser","wuser123","a_123","App_123"]
    es = Elasticsearch([host], port=port, connection_class=RequestsHttpConnection,
                       http_auth=(user, pw), use_ssl=True, verify_certs=False, timeout=120, retry_on_timeout=True, max_retries=3)

    dtn=datetime.datetime.now()
    lt_date = datetime.datetime(day=dtn.day, year=dtn.year, month=dtn.month)
    duration1 = datetime.timedelta(days=90)
    gte_date = lt_date - duration1

    gte_date = gte_date.strftime("%Y-%m-%dT%H:%M:%S")

    systems_ips = sag_systems
    length = len(systems_ips)

    divisor = 1000
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

    with open('query.json') as json_file:
        query = json.load(json_file)

    asd = 0
    for s in slices:
        query['bool']['filter'][0]['terms']['source.ip'] = s
        with open('query%d.json' % (asd + 1), 'w') as outfile:
            json.dump(query, outfile)

        with open('query%d.json' % (asd + 1)) as json_file:
            query = json.load(json_file)

        for i in range(4):
            download_index(es=es,query=query,index="business_partner_00%d" % (i+1),nth=(i+1),sort="_doc",gte_date=gte_date,asd=asd,path=path)
        asd=asd+1
    print("Done!")

def download_index(es,query, index, nth, sort, gte_date,asd,path):
    resp = es.search(query=query,index=index,sort=sort,size=10000)
    #hits_len = resp['hits']['total']['value']
    hits_len = len(resp['hits']['hits'])
    print("Got %d Hits:" % hits_len)
    seq = 0
    hits = resp['hits']['hits']

    filepath = path / (hit_json % (asd, gte_date, nth, seq))
    with filepath.open('w') as outfile:
        for b in hits:
            json.dump(flattenhit(b), outfile)
            outfile.write("\n")
    seq = seq + 1

    while hits_len >= 10000:
        search_after=resp['hits']['hits'][-1]['sort']
        resp = es.search(index=index,sort=sort,search_after=search_after,size=10000)
        # hits_len = resp['hits']['total']['value']
        hits_len = len(resp['hits']['hits'])
        print("Got %d Hits:" % hits_len)
        hits = resp['hits']['hits']

        filepath = path / (hit_json % (asd, gte_date, nth, seq))
        if hits_len==0:
            print("Not creating "+filepath.name)
        else:
            with filepath.open('w') as outfile:
                # json.dump(buckets)
                for b in hits:
                    json.dump(flattenhit(b), outfile)
                    outfile.write("\n")
        seq = seq + 1

def flattenhit(h):
    s=h['_source']['source']['ip']
    d=h['_source']['destination']['ip']
    return {"source_ip":s,"dest_ip":d}

if __name__ == '__main__':
    main(Path("hits/"))

