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

    divisor = 1000

    slices = to_slices(divisor, systems_ips)

    with open('query.json') as json_file:
        query = json.load(json_file)

    with open('aggs.json') as json_file:
        aggs = json.load(json_file)

    slices_index = 0
    for s in slices:
        query['bool']['filter'][0]['terms']['source.ip'] = s
        with open('query%d.json' % (slices_index + 1), 'w') as outfile:
            json.dump(query, outfile)
        
        #download_index(es=es,query=query,index="energy-checkpoint",nth=1,sort="_doc",gte_date=gte_date,asd=asd,path=path)
        download_buckets(es=es,query=query,aggs=aggs,gte_date=gte_date,slices_index=slices_index)
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
                    if flattenhit(b) is not None:
                        json.dump(flattenhit(b), outfile)
                        outfile.write("\n")
        seq = seq + 1

def download_buckets(es,query,aggs,gte_date,slices_index):
    buckets_len = 10000
    seq = 0
    while buckets_len >= 10000:
        resp = es.search(query=query, index="energy-checkpoint", size=0, aggs=aggs)
        hits_len = resp['hits']['total']['value']
        print("Got %d Hits:" % hits_len)
        buckets = resp['aggregations']['my-buckets']['buckets']
        buckets_len = buckets.__len__()

        with open('hits/hit%s_%d_%d.json' % (gte_date,slices_index,seq), 'w') as outfile:
            # json.dump(buckets)
            for b in buckets:
                json.dump(flattenbucket(b), outfile)
                outfile.write("\n")
        seq = seq + 1

        if (10000<=buckets_len):
            with open('hits/after_key.json', 'a') as outfile:
                #check if after_key.json gets overwritten instead of appended to
                json.dump(resp['aggregations']['my-buckets']['after_key'], outfile)
                outfile.write("\n")

            aggs['my-buckets']['composite']['after'] = {}
            aggs['my-buckets']['composite']['after']['source_ip'] = resp['aggregations']['my-buckets']['after_key'][
                'source_ip']
            aggs['my-buckets']['composite']['after']['dest_ip'] = resp['aggregations']['my-buckets']['after_key']['dest_ip']

def flattenbucket(b):
    s=b['key']['source_ip']
    d=b['key']['dest_ip']
    return {"source_ip":s,"dest_ip":d}

def flattenhit(h):
    try:
        s=h['_source']['source']['ip']
        d=h['_source']['destination']['ip']
        return {"source_ip":s,"dest_ip":d}
    except Exception as e:
        print("Error in flattenhit: %s\t%s" % (h["_index"],h["_id"]))
        return None

if __name__ == '__main__':
    main(Path("hits/"))

