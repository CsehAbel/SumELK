import json

import generate_queries
import import_rules
import resolveIpToName
import systems_group
import qc_to_sql
from sqlalchemy import create_engine
import secrets
import main as hits
import bulk_json_to_df
import eagle_filter
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
    # first run SGRE to unpack se_ruleset
    filepath_qc = get_cli_args().qualitycheck
    qc_to_sql.main(filepath_qc)
    path = "./Network-CST-P-SAG-Energy.json"
    import_rules.main(path)

    #fill mysql tables eagle, snic_export, run eagle_comparison.sql
    filepath_qc = "20220627-snic_ip_network_assignments.csv"
    eagle_filter.main(filepath_qc)
    eagle_filter.snic_to_sql(filepath_qc)

    # download hits to hits/...json
    hits.main()
    # .json to mysql table 'ip'
    path = "/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/hits/"
    regex = "^hit.*"
    bulk_json_to_df.main(path,regex)


    onlyinnew = generate_queries.read_query1to4()
    #new_transform.json
    generate_queries.save_new_transform_json(onlyInNew=onlyinnew)
    #upload all_red_networks systems to mysql systems table
    generate_queries.main()

    # resolving ip to fqdn for white_apps
    # each time the ip-fqdn pair will be appended to CSV_DB->src_dns
    # resolveIpToName.resolve_white_apps()

if __name__ == "__main__":
    main()
