import json

import resolveIpToName
import systems_group
import qc_to_sql
from sqlalchemy import create_engine
import secrets
import main as hits
import bulk_json_to_df
from sqlalchemy import create_engine

import secrets
import pandas
import shlex
import sys
import argparse

def get_cli_args():
    parser = argparse.ArgumentParser("Unpacking Quality Check xlsx")
    parser.add_argument(
        '--qualitycheck', dest="qualitycheck", type=str, required=True,
        help="Path of QualityCheck.xlsx"
    )
    #ToDo add command line argument for excel file
    args = parser.parse_args(shlex.split(" ".join(sys.argv[1:])))
    return args

def main():
    # downloads SecureTrack
    # where rule_name like a.* and like wuser.*  and not like atos_vuln_scan
    # to CSV_DB -> st_ports
    # systems_group.dest_ports_to_file()
    # first run SGRE to unpack se_ruleset
    # filepath_qc = "se_ruleset_unpacked22Mar2022.xlsx"
    filepath_qc = get_cli_args().qualitycheck
    qc_to_sql.main(filepath_qc)
    #downloading securetrack dest_ip,port
    systems_group.dest_ports_to_file()

    # download hits to hits/...json
    # hits.main()
    # /mnt/c/ProgramData/MySQL/MySQL Server 8.0/Uploads

    systems_group.save_new_transform_json()

    # resolving ip to fqdn for white_apps
    # each time the ip-fqdn pair will be appended to CSV_DB->src_dns
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "CSV_DB"), pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    resolveIpToName.resolve_white_apps(sqlEngine, dbConnection)

if __name__ == "__main__":
    main()
