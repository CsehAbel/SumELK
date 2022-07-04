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
import re

import pandas
from sqlalchemy import create_engine

import ip_utils
from pathlib import Path

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


#system_groups.py all_red_networks_systems() rewritten
def read_query1to4():
    systems_ips = systems_group.get_systems_ip_list()
    p1 = ["old_darwin_transform.json"]
    trsfrm_path = lambda x: Path(x).absolute()
    p2=[trsfrm_path(y) for y in p1]
    #query1…4 altal lettek letoltve, a transform job 1-4 altal lettek letöltve
    list_old = []
    #q for query
    for q in p2:
        with q.open("r") as infile:
            query=json.load(infile)
            prefixlist=query['bool']['filter']['terms']['source.ip']
            for line in prefixlist:
                patternPrefixCIDR = re.compile('^(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/(\d+))$')
                # [\s"]* anstatt \s*
                resultPrefix = patternPrefixCIDR.match(line)
                if resultPrefix:
                    list_old.append(line)
                else:
                    raise ValueError


    # need to be added to new transform
    #{ new all_red-networks systems } - { 4xtransform job business_partner_001-004 }
    # save_new_transform_json() new_transform.json
    onlyInNew = set(systems_ips) - set(list_old)
    return onlyInNew

#moved from systems_group.py
#onlyinold_to_sql() not needed anymore, table should be deleted
#onlyInNew needs to be exploded to use as left join filter for the table hits
def save_new_transform_json(onlyInNew):

    with open('transform.json') as json_file:
        transform = json.load(json_file)
    print("Done reading transform.json!")
    #275
    transform['bool']['filter']['terms']['source.ip'] = list(onlyInNew)

    with open('old_darwin_transform.json', 'w') as outfile:
        json.dump(transform, outfile)
    print("Done writing darwin_transform.json!")

#systems_group.py onlyinold_to_sql() repurposed
def systems_to_sql(systems):
    list_unpacked_ips = []
    for line in systems:
        patternPrefixCIDR = re.compile('^(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/(\d+))$')
        # [\s"]* anstatt \s*
        resultPrefix = patternPrefixCIDR.match(line)
        if not resultPrefix:
            raise ValueError("onlyInOld.json not matching regex")

        prefix2 = resultPrefix.group(2)
        cidr = resultPrefix.group(3)
        cidr2 = ip_utils.correctAndCheckMatchedMask(cidr)
        base = ip_utils.integerToDecimalDottedQuad(
            ip_utils.decimalDottedQuadToInteger(prefix2) & ip_utils.makeIntegerMask(
                cidr2))
        if base != prefix2:
            print("Not a network Adresse (possible ip base %s)" % base)

        int_prefix_top = (~ip_utils.makeIntegerMask(
            cidr2)) | ip_utils.decimalDottedQuadToInteger(prefix2)
        if int_prefix_top - 2 * 32 == -4117887025:
            print("Test singed to unsigned conversion")
            # ToDo breakpoint setzen, Werte die die for Schleife ausspuckt mit den erwarteten Ergebnisse zu vergleichen
            # Modified
            #    decimalDottedQuadToInteger()
            # to convert signed integers to unsigned.
            # Das Folgende ist redundant, überreichlich, ersetzt:
            #   int_prefix_top == -4117887025:
            #   if int_prefix_top < 0:
            #      int_prefix_top = int_prefix_top + (2**32)

        prefix_top = ip_utils.integerToDecimalDottedQuad(int_prefix_top)
        # print("netw.adrr.:{}".format(base))
        for j in range(ip_utils.decimalDottedQuadToInteger(base) + 1,
                       ip_utils.decimalDottedQuadToInteger(
                           ip_utils.integerToDecimalDottedQuad(int_prefix_top)) + 1):
            list_unpacked_ips.append(ip_utils.integerToDecimalDottedQuad(j))

    df = pandas.DataFrame(list_unpacked_ips)
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "DARWIN_DB"), pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    df.to_sql("systems", dbConnection, if_exists='replace', index=True)

def main():
    #onlyinnew=read_query1to4()
    #save_new_transform_json(onlyInNew=onlyinnew)
    systems_to_sql(systems=systems_group.get_systems_ip_list())


if __name__=="__main__":
    main()