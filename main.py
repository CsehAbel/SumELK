#!/home/scripts/ticket_automatisierung/bin/python3
import datetime
import logging
import argparse
import math
import shlex
import sys
import os

import pandas
from pytos.common.functions.config import Secure_Config_Parser
from pytos.common.logging.definitions import COMMON_LOGGER_NAME
from pytos.common.logging.logger import setup_loggers
from pytos.securechange.helpers import Secure_Change_Helper
from pytos.securechange.xml_objects.rest import Group_Change_Member_Object
from pytos.securetrack.helpers import Secure_Track_Helper
from pytos.common.definitions.xml_tags import Attributes
from pytos.securechange.xml_objects.rest import Group_Change_Member_Object,Group_Change_Node,Step_Field_Multi_Group_Change
from pytos.common.base_types import XML_List

from elasticsearch import Elasticsearch
import json
from ssl import create_default_context
from elasticsearch import RequestsHttpConnection

import secrets
import systems_group


sc_helper = Secure_Change_Helper("cofw.siemens.com", (secrets.sc_u, secrets.sc_pw))
st_helper = Secure_Track_Helper("cofw-track.siemens.com", (secrets.st_u,secrets.st_pw))

log_file_path="/home/scripts/"
log_file_name="pytos_logger_sumelk.log"
config_file_path='pytos.conf'

logger = logging.getLogger(COMMON_LOGGER_NAME)
conf = Secure_Config_Parser(config_file_path=config_file_path)
setup_loggers(conf.dict("log_levels"),log_file_path,log_file_name,log_to_stdout=True)  # cli_args.debug)

# log_file2="/home/scripts/notfound.log"
#
# logger2 = logging.getLogger(__name__)
# logger2.setLevel(logging.DEBUG)
# formatter = logging.Formatter('%(asctime)s:%(name)s:%(message)s')
# file_handler = logging.FileHandler(log_file2)
# file_handler.setLevel(logging.INFO)
# file_handler.setFormatter(formatter)
# stream_handler = logging.StreamHandler()
# stream_handler.setFormatter(formatter)
# logger2.addHandler(file_handler)
# logger2.addHandler(stream_handler)
#
# logger2.info("Script called.")

user=secrets.sc_u
pw=secrets.sc_pw
host='sn1hot03.ad001.siemens.net'
port='9200'

def main():

    device_name = "CST-P-SAG-Energy"
    #device_id = st_helper.get_device_id_by_name(device_name)
    #rules=st_helper.get_rules_for_device(device_id)
    #use aggregation dest_ip(source_ip), look at the results with pandas scientific viewer in debug mode
    #(query-range) + (query-rule_name)
    #GET /my-index-000001/_search?typed_keys The response returns the aggregation type as a prefix to the aggregation’s name.
    #print matched iterating: lista["i_f","vuser","wuser123","a_123","App_123"]

    es = Elasticsearch([host], port=port, connection_class=RequestsHttpConnection,
                       http_auth=(user, pw), use_ssl=True, verify_certs=False, timeout=120, retry_on_timeout=True, max_retries=3)

    with open('query.json') as json_file:
        query = json.load(json_file)

    with open('aggs.json') as json_file:
        aggs = json.load(json_file)

    with open('aggs_ports.json') as json_file:
        aggs_ports = json.load(json_file)

    #lt_date = datetime.datetime(day=23, year=2022, month=1)
    dtn=datetime.datetime.now()
    lt_date = datetime.datetime(day=dtn.day, year=dtn.year, month=dtn.month)
    duration1 = datetime.timedelta(days=15)
    gte_date = lt_date - duration1

    #lt_date = lt_date - duration1
    #duration2 = datetime.timedelta(days=30)
    #gte_date = lt_date - duration2

    gte_date = gte_date.strftime("%Y-%m-%dT%H:%M:%S")
    lt_date = lt_date.strftime("%Y-%m-%dT%H:%M:%S")
    #query['bool']['filter'][1]['range']['@timestamp']['gte']=gte_date
    #query['bool']['filter'][1]['range']['@timestamp']['lt']=lt_date

    systems_ips=systems_group.get_systems_ip_list()
    length = len(systems_ips)

    divisor=1000
    quotient,rest = divmod(length,divisor)

    slices=[] #[[list[0],...list[999]],]
    lower_bound=0
    for i in range(quotient+1):
        upper_bound=(i+1)*divisor
        if upper_bound<length:
            slices.append(systems_ips[slice(lower_bound,upper_bound,1)])
        else:
            slices.append(systems_ips[slice(lower_bound, length,1)])
        lower_bound=upper_bound

    asd=0
    for s in slices:
        query['bool']['filter'][0]['terms']['source.ip']=s
        with open('query%d.json' %(asd+1), 'w') as outfile:
            json.dump(query, outfile)
       
        with open('query%d.json' %(asd+1)) as json_file:
            query = json.load(json_file)

        download_buckets_ports(es,query,aggs_ports,gte_date,lt_date)

        asd=asd+1
    print("Done!")

def download_buckets(es,query,aggs,gte_date,lt_date):
    buckets_len = 10000
    seq = 0
    while buckets_len >= 10000:
        resp = es.search(query=query, index="energy-checkpoint", size=0, aggs=aggs)
        hits_len = resp['hits']['total']['value']
        print("Got %d Hits:" % hits_len)
        buckets = resp['aggregations']['my-buckets']['buckets']
        buckets_len = buckets.__len__()

        with open('buckets_saved/bucket%s_%d.json' % (gte_date, seq), 'w') as outfile:
            # json.dump(buckets)
            for b in buckets:
                json.dump(flattenbucket(b), outfile)
                outfile.write("\n")
        seq = seq + 1

        if (10000<=buckets_len):
            with open('buckets_saved/after_key.json', 'a') as outfile:
                json.dump(resp['aggregations']['my-buckets']['after_key'], outfile)
                outfile.write("\n")

            aggs['my-buckets']['composite']['after'] = {}
            aggs['my-buckets']['composite']['after']['source_ip'] = resp['aggregations']['my-buckets']['after_key'][
                'source_ip']
            aggs['my-buckets']['composite']['after']['dest_ip'] = resp['aggregations']['my-buckets']['after_key']['dest_ip']

def download_buckets_ports(es,query,aggs,gte_date,lt_date):
    buckets_len = 10000
    seq = 0
    while buckets_len >= 10000:
        resp = es.search(query=query, index="energy-checkpoint", size=0, aggs=aggs)
        hits_len = resp['hits']['total']['value']
        print("Got %d Hits:" % hits_len)
        buckets = resp['aggregations']['my-buckets']['buckets']
        buckets_len = buckets.__len__()

        with open('buckets_saved/bucket%s_%d.json' % (gte_date, seq), 'w') as outfile:
            # json.dump(buckets)
            for b in buckets:
                json.dump(flattenbucket_ports(b), outfile)
                outfile.write("\n")
        seq = seq + 1

        if (10000<=buckets_len):
            with open('buckets_saved/after_key.json', 'a') as outfile:
                json.dump(resp['aggregations']['my-buckets']['after_key'], outfile)
                outfile.write("\n")

            aggs['my-buckets']['composite']['after'] = {}
            aggs['my-buckets']['composite']['after']['source_ip'] = resp['aggregations']['my-buckets']['after_key'][
                'source_ip']
            aggs['my-buckets']['composite']['after']['dest_ip'] = resp['aggregations']['my-buckets']['after_key']['dest_ip']
            aggs['my-buckets']['composite']['after']['source_port'] = resp['aggregations']['my-buckets']['after_key'][
                'source_port']
            aggs['my-buckets']['composite']['after']['dest_port'] = resp['aggregations']['my-buckets']['after_key'][
                'dest_port']


def flattenbucket(b):
    s=b['key']['source_ip']
    d=b['key']['dest_ip']
    return {"source_ip":s,"dest_ip":d}

def flattenbucket_ports(b):
    s=b['key']['source_ip']
    d=b['key']['dest_ip']
    w = b['key']['source_port']
    a = b['key']['dest_port']
    return {"source_ip":s,"dest_ip":d,"source_port":w,"dest_port":a}

def filteredresults():
    es = Elasticsearch([host], port=port, connection_class=RequestsHttpConnection,
                       http_auth=(user, pw), use_ssl=True, verify_certs=False)

    with open('query.json') as json_file:
        data = json.load(json_file)

    resp = es.search(query=data, index="energy-checkpoint", size=10000)
    print("Got %d Hits:" % resp['hits']['total']['value'])
    return resp

if __name__ == '__main__':
    main()

