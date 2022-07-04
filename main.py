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

def main():
    #print matched iterating: lista["i_f","vuser","wuser123","a_123","App_123"]
    es = Elasticsearch([host], port=port, connection_class=RequestsHttpConnection,
                       http_auth=(user, pw), use_ssl=True, verify_certs=False, timeout=120, retry_on_timeout=True, max_retries=3)

    dtn=datetime.datetime.now()
    lt_date = datetime.datetime(day=dtn.day, year=dtn.year, month=dtn.month)
    duration1 = datetime.timedelta(days=90)
    gte_date = lt_date - duration1

    gte_date = gte_date.strftime("%Y-%m-%dT%H:%M:%S")

    for i in range(1):
        download_index(es=es,index="darwin_business_partner",nth=(i+1),sort="_doc",gte_date=gte_date)
    
    print("Done!")

def download_index(es,index,nth,sort,gte_date):
    resp = es.search(index=index,sort=sort,size=10000)
    #hits_len = resp['hits']['total']['value']
    hits_len = len(resp['hits']['hits'])
    print("Got %d Hits:" % hits_len)
    seq = 0
    hits = resp['hits']['hits']

    p = "darwin_hits"
    path = Path(p).absolute()
    filepath = path / ('hit_00%d_%s_%d.json' % (nth, gte_date, seq))
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

        if hits_len==0:
            print("Not creating darwin_hits/hit_00%d_%s_%d.json" % (nth,gte_date,seq))
        else:
            with open('darwin_hits/hit_00%d_%s_%d.json' % (nth,gte_date,seq), 'w') as outfile:
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
    main()

