import subprocess
import sys

import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.testing import db_spec

import secrets
import csv
import dns.resolver, dns.reversename

def ip2dns(ip): #defthw99m5bsrv.ad001.siemens.net 139.23.160.99

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["ad101.siemens-energy.net", "ad001.Siemens.net", "139.25.226.62"]
    #ip='139.21.146.17'
    n = dns.reversename.from_address(ip)
    try:
        names = dns.resolver.query(n, "PTR")
    except dns.resolver.NXDOMAIN as e:
        pass
    except dns.resolver.NoNameservers as e2:
        pass
    else:
        if 1<names.response.answer.__len__():
            cc=0
            ll=[]
            for answer in names.response.answer:
                for item in answer.items:
                    if item.rdtype==12:
                        cc=cc+1
                        xx=".".join(
                            map(lambda x: x.decode("utf-8"), item.target.labels)).rstrip("\.")
                        ll.append(xx)
            if cc>1:
                print()
            elif cc==1:
                return ll[0]
            else:
                print()
        return ".".join(map(lambda x: x.decode("utf-8"),names.response.answer[0].items[0].target.labels)).rstrip("\.")

    #return names


def main():
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "CSV_DB"), pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    wa_ips = pd.read_sql_query("SELECT src_ip FROM ip_unique GROUP BY src_ip", dbConnection)
    wa_ips['dns'] = wa_ips["src_ip"].map(lambda a: ip2dns(a))
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "CSV_DB"), pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    wa_ips.to_sql("src_dns", dbConnection, if_exists='replace', index=True)
    # print("")


if __name__=="__main__":
    main()