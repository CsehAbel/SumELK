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
import json
import secrets
import systems_group

user=secrets.sc_u
pw=secrets.sc_pw
host='sn1hot03.ad001.siemens.net'
port='9200'

#moved from systems_group.py
#onlyinold_to_sql() not needed anymore, table should be deleted
#onlyInNew needs to be exploded to use as left join filter for the table hits
def save_new_transform_json(sag_systems,new_name):

    with open('transform.json') as json_file:
        transform = json.load(json_file)
    print("Done reading transform.json!")
    #393
    transform['bool']['filter']['terms']['source.ip'] = list(sag_systems)

    with open(new_name, 'w') as outfile:
        transform2 = json.dumps(transform, indent=4)  # ,sort_keys=True)
        outfile.write(transform2)
    print("Done writing %s!" % new_name)

def systems_to_sql(systems,table_name, db_name):
    list_unpacked_ips = []
    for line in systems:
        patternPrefixCIDR = re.compile('^(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/(\d+))$')
        # [\s"]* anstatt \s*
        resultPrefix = patternPrefixCIDR.match(line)
        if not resultPrefix:
            raise ValueError("onlyInOld.json not matching regex")

        prefix2 = resultPrefix.group(2)
        cidr = resultPrefix.group(3)
        cidr = int(cidr)
        base = ip_utils.int2ip(
            ip_utils.ip2int(prefix2) & ip_utils.makeIntegerMask(
                cidr))
        if base != prefix2:
            print("Not a network Adresse (possible ip base %s)" % base)

        int_prefix_top = (~ip_utils.makeIntegerMask(
            cidr)) | ip_utils.ip2int(prefix2)
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

        prefix_top = ip_utils.int2ip(int_prefix_top)
        # print("netw.adrr.:{}".format(base))
        for j in range(ip_utils.ip2int(base) + 1,
                       ip_utils.ip2int(
                           ip_utils.int2ip(int_prefix_top)) + 1):
            list_unpacked_ips.append(ip_utils.int2ip(j))

    df = pandas.DataFrame(list_unpacked_ips)
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", db_name), pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    df.to_sql(table_name, dbConnection, if_exists='replace', index=True)