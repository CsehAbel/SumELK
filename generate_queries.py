#Get all Prefixes already in transforms
#Created Alias for business_partner_001-4 indices
#Generate onlyInOld,onlyInNew using source ip prefix buckets of existing documents
#in indices created by transforms

# all_red_networks systems tartalmaz majd olyan source ip-ket
# amik query1…4 altal nem lett letöltve energy_checkpoint-bol,
# ezeket egy uj query-be fel kell venni

# query1..4-ben lesznek olyan source-ip-k amiket nem szabad többe query1…4 -nek letölteni,
# de megis le lettek töltve, ezek azok amik all_red_networks systems mar nincsenek benne,
# de a transform-ban benne vannak



from elasticsearch import Elasticsearch
import json
from ssl import create_default_context
from elasticsearch import RequestsHttpConnection

import secrets
import systems_group

user=secrets.sc_u
pw=secrets.sc_pw
host='sn1hot03.ad001.siemens.net'
port='9200'

def wasd():
    with open('query.json') as json_file:
        query = json.load(json_file)
    wasd(query)

#Generate multiple queries
def wasd(query):


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

#download bucket aggregation where each bucket is a ip+prefix of source ip
def download_buckets():
    es = Elasticsearch([host], port=port, connection_class=RequestsHttpConnection,
                       http_auth=(user, pw), use_ssl=True, verify_certs=False, timeout=120, retry_on_timeout=True,
                       max_retries=3)
    with open('aggs.json') as json_file:
        aggs= json.load(json_file)

    with open('query.json') as json_file:
        query = json.load(json_file)

    #alias for business_partner_001-4 indices
    index="business_partner"

    download_buckets(es,index,query,aggs)

#repurpose for bucketing source ip into ip range buckets
def download_buckets(es,index,query,aggs):
    buckets_len = 10000
    seq = 0
    while buckets_len >= 10000:
        resp = es.search(query=query, index=index, size=0, aggs=aggs)
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