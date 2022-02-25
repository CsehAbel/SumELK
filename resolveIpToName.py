import subprocess
import sys

import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.testing import db_spec

import secrets
import csv

def ip2dns(): #defthw99m5bsrv.ad001.siemens.net 139.23.160.99
    ipl = pd.read_clipboard(header=None,names=['ip'])
    ipl.to_csv("mnt/c/Users/z004a6nh/PycharmProjects/SumELK/ip.txt", index = False, header = False)
    p = subprocess.Popen(["powershell.exe",
                          "/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/pyip2dns.ps1"],
                         stdout=sys.stdout)
    p.communicate()
    dns = pd.read_csv("mnt/c/Users/z004a6nh/PycharmProjects/SumELK/dns.csv",sep=';') #get dns after running get-dns-by-ips.ps1
    print(dns)

def main():
    #ip2dns()
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "CSV_DB"), pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    wa_ips=pd.read_sql_query("SELECT IPs FROM white_apps_se_ruleset",dbConnection)
    wa_ips=wa_ips["IPs"]
    wa_ips.to_csv("dns.csv",index=False,header=False,quoting=csv.QUOTE_NONE, quotechar="")
    print("")

if __name__=="__main__":
    main()