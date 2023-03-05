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

def save_new_transform_json(sag_systems,new_name):
    with open('transform.json') as json_file:
        transform = json.load(json_file)
    print("Done reading transform.json!")
    transform['bool']['filter']['terms']['source.ip'] = list(sag_systems)

    with open(new_name, 'w') as outfile:
        transform2 = json.dumps(transform, indent=4)  # ,sort_keys=True)
        outfile.write(transform2)
    print("Done writing %s!" % new_name)

def systems_to_sql(systems,table_name, db_name):
    df = pandas.DataFrame(systems)
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", db_name), pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    df.to_sql(table_name, dbConnection, if_exists='replace', index=True)