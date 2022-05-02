#!/home/scripts/ticket_automatisierung/bin/python3
from datetime import datetime
import argparse
import pathlib
import shlex
import sys
from pathlib import Path
from elasticsearch import Elasticsearch
from elasticsearch import RequestsHttpConnection
import json

import secrets

user=secrets.sc_u
pw=secrets.sc_pw
host='sn1hot03.ad001.siemens.net'
port='9200'

def valid_date(s):
    try:
        return datetime.strptime(s, "%H:%M-%d-%m-%Y")
    except ValueError:
        msg = "expected format HH:MM-dd-mm-yyyy, not valid format: {0!r}".format(s)
        raise argparse.ArgumentTypeError(msg)

def get_cli_args():
    parser = argparse.ArgumentParser("Query Elastic Yellow Indices, see --help for options")
    choices=["sfs-yellow-checkpoint"
    ,"siemens-yellow-checkpoint"
    ,"express-yellow-checkpoint"
    ,"cz-yellow-checkpoint"
    ,"energy-yellow-checkpoint"]
    parser.add_argument('--firewall','-f',dest="fw", type=str, required=True,
                        choices = choices,
                        help='elastic alias for elastic index(sfs-...,siemens-...,express-...,cz-...,energy-...)')
    parser.add_argument('--gte_date', '-g', dest="gte_date", type=valid_date, required=True,
                        help='greater than equal date HH:MM-dd-mm-yyyy')
    parser.add_argument('--lt_date', '-l', dest="lt_date", type=valid_date, required=True,
                        help='lower than date HH:MM-dd-mm-yyyy')
    parser.add_argument(
        "--data_dir",
        dest="data_dir",
        type=lambda p: Path(p).absolute(),
        required=True,
        help="Path to the data directory",
    )

    args = parser.parse_args(shlex.split(" ".join(sys.argv[1:])))
    return args


def main():
    es = Elasticsearch([host], port=port, connection_class=RequestsHttpConnection,
                       http_auth=(user, pw), use_ssl=True, verify_certs=False, timeout=120, retry_on_timeout=True, max_retries=3)

    with open('query.json') as json_file:
        query = json.load(json_file)

    with open('aggs.json') as json_file:
        aggs = json.load(json_file)

    #option firewall-name, start, stop datum, Ziel-Verzeichniss
    #wegen des Speicherverbrauchs sollte Sachen gelöscht werden die älter als 30 Tage sind
    #lt_date = datetime.datetime(day=23, year=2022, month=1)

    gte_date = get_cli_args().gte_date
    lt_date = get_cli_args().lt_date
    gte_date = gte_date.strftime("%Y-%m-%dT%H:%M:%S")
    lt_date = lt_date.strftime("%Y-%m-%dT%H:%M:%S")
    query["bool"]['filter']['range']['@timestamp']['gte']=gte_date
    query["bool"]['filter']['range']['@timestamp']['lt']=lt_date

    indices=["sfs-yellow-checkpoint"
    ,"siemens-yellow-checkpoint"
    ,"express-yellow-checkpoint"
    ,"cz-yellow-checkpoint"
    ,"energy-yellow-checkpoint"
    ]

    current_index=get_cli_args().fw

    #Verzeichnis erstellen anhand angegebenes Datei-Namens
    p = get_cli_args().data_dir
    p.mkdir(parents=False, exist_ok=True)

    download_index(dir_path=p,es=es,index=current_index,query=query,sort="_doc",gte_date=gte_date,fields=[
      "source.ip",
      "destination.ip",
      "source.port",
      "destination.port",
      "rule.name",
      "observer.ingress.interface.name",
      "input.type"
    ])
    
    print("Done!")


def download_buckets(es,index, query, aggs, gte_date):
    buckets_len = 10000
    seq = 0
    while buckets_len >= 10000:
        resp = es.search(query=query, index=index, size=0, aggs=aggs)
        hits_len = resp['hits']['total']['value']
        print("Got %d Hits:" % hits_len)
        buckets = resp['aggregations']['my-buckets']['buckets']
        buckets_len = buckets.__len__()

        with open('yellow/%s_%s_%d.json' % (index,gte_date, seq), 'w') as outfile:
            for b in buckets:
                b=flattenbucket(b)
                b["index"]=index
                json.dump(b, outfile)
                outfile.write("\n")
        seq = seq + 1

        if (10000 <= buckets_len):
            aggs['my-buckets']['composite']['after'] = {}
            aggs['my-buckets']['composite']['after']['source_ip'] = resp['aggregations']['my-buckets']['after_key'][
                'source_ip']
            aggs['my-buckets']['composite']['after']['dest_ip'] = resp['aggregations']['my-buckets']['after_key'][
                'dest_ip']
            aggs['my-buckets']['composite']['after']["source_port"] = resp['aggregations']['my-buckets']['after_key'][
                "source_port"]
            aggs['my-buckets']['composite']['after']["dest_port"] = resp['aggregations']['my-buckets']['after_key'][
                "dest_port"]
            aggs['my-buckets']['composite']['after']["protocol"] = resp['aggregations']['my-buckets']['after_key'][
                "protocol"]
            aggs['my-buckets']['composite']['after']["rule_name"] = resp['aggregations']['my-buckets']['after_key'][
                "rule_name"]
            aggs['my-buckets']['composite']['after']["interface"] = resp['aggregations']['my-buckets']['after_key'][
                "interface"]


def download_index(dir_path,es,index,sort,gte_date,query,fields):
    resp = es.search(index=index,query=query,sort=sort,size=10000,fields=fields)
    #hits_len = resp['hits']['total']['value']
    hits_len = len(resp['hits']['hits'])
    print("Got %d Hits:" % hits_len)
    seq = 0
    hits = resp['hits']['hits']

    fn = '%s_%s_%d.json' % (index, gte_date, seq)
    filepath = dir_path / fn
    with filepath.open("w", encoding="utf-8") as f:
        for b in hits:
            b=flattenhit(b)
            json.dump(b, f)
            f.write("\n")
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

