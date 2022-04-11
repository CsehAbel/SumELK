#!/home/scripts/ticket_automatisierung/bin/python3
import datetime

import pandas
from elasticsearch import Elasticsearch
import json

from elasticsearch import RequestsHttpConnection

import secrets

user=secrets.sc_u
pw=secrets.sc_pw
host='sn1hot03.ad001.siemens.net'
port='9200'

def main():

    es = Elasticsearch([host], port=port, connection_class=RequestsHttpConnection,
                       http_auth=(user, pw), use_ssl=True, verify_certs=False, timeout=120, retry_on_timeout=True, max_retries=3)

    with open('query.json') as json_file:
        query = json.load(json_file)

    with open('aggs.json') as json_file:
        aggs = json.load(json_file)

    #lt_date = datetime.datetime(day=23, year=2022, month=1)
    dtn=datetime.datetime.now()
    lt_date = datetime.datetime(day=dtn.day, year=dtn.year, month=dtn.month)
    duration1 = datetime.timedelta(minutes=10)
    gte_date = lt_date - duration1

    gte_date = gte_date.strftime("%Y-%m-%dT%H:%M:%S")
    lt_date = lt_date.strftime("%Y-%m-%dT%H:%M:%S")
    query["bool"]['filter']['range']['@timestamp']['gte']=gte_date
    query["bool"]['filter']['range']['@timestamp']['lt']=lt_date

    indices=["sfs-yellow-checkpoint-000001"
    ,"siemens-yellow-checkpoint-000001"
    ,"express-yellow-checkpoint-000001"
    ,"cz-yellow-checkpoint-000001"
    ,"energy-yellow-checkpoint-000001"
    ]

    for i in range(indices.__len__()):
        current_index=indices[i]
        download_index(es=es,index=current_index,query=query,sort="_doc",gte_date=gte_date,fields=[
          "source.ip",
          "destination.ip",
          "source.port",
          "destination.port",
          "rule.name",
          "observer.ingress.interface.name",
          "input.type"
        ])
    
    print("Done!")





def download_index(es,index,sort,gte_date,query,fields):
    resp = es.search(index=index,query=query,sort=sort,size=10000,fields=fields)
    #hits_len = resp['hits']['total']['value']
    hits_len = len(resp['hits']['hits'])
    print("Got %d Hits:" % hits_len)
    seq = 0
    hits = resp['hits']['hits']
    with open('yellow/%s_%s_%d.json' % (index, gte_date, seq), 'w') as outfile:
        for b in hits:
            b=flattenhit(b)
            json.dump(b, outfile)
            outfile.write("\n")
    seq = seq + 1

    while hits_len >= 10000:
        search_after=resp['hits']['hits'][-1]['sort']
        resp = es.search(index=index,search_after=search_after,query=query,sort=sort,size=10000,fields=fields)
        # hits_len = resp['hits']['total']['value']
        hits_len = len(resp['hits']['hits'])
        print("Got %d Hits:" % hits_len)
        hits = resp['hits']['hits']

        with open('yellow/%s_%s_%d.json' % (index,gte_date,seq), 'w') as outfile:
            # json.dump(buckets)
            for b in hits:
                b = flattenhit(b)
                json.dump(b, outfile)
                outfile.write("\n")
        seq = seq + 1

def flattenhit(h):
            # "field": "source.port",
            # "field": "destination.port",
            # "field": "observer.ingress.interface.name",
            # "field": "input.type",
            # "field": "rule.name"
        h=h['fields']
        try:
            s = h["source.ip"][0]
        except KeyError as e:
            print("")
        d = h["destination.ip"][0]
        if "source.port" in h:
            sp = h["source.port"][0]
        else:
            sp = None
        if "destination.port" in h:
            dp = h["destination.port"][0]
        else:
            dp = None
        if "input.type" in h:
            p = h["input.type"][0]
        else:
            p = None
        if "observer.ingress.interface.name" in d:
            r = h["observer.ingress.interface.name"][0]
        else:
            r = None
        if "rule.name" in h:
            i = h["rule.name"][0]
        else:
            i = None
        return {"source_ip": s, "dest_ip": d, "source_port": sp,
                "dest_port": dp, "protocol": p, "rule_name": r, "interface": i
                }


def flattenbucket(h):
    h=h['key']
    return h

if __name__ == '__main__':
    main()

