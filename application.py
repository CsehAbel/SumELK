import json

import generate_queries
import import_rules
import systems_group
import qc_to_sql
from sqlalchemy import create_engine
import secrets
import main as hits
import bulk_json_to_df
from sqlalchemy import create_engine
import darwin_resolve
import eagle_filter

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
    path = "./Network-CST-P-SAG-Darwin.json"
    import_rules.main(path)

    # download hits to hits/...json
    hits.main()
    # .json to mysql table 'ip'
    path = "/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/darwin_hits/"
    regex = "^hit.*"
    bulk_json_to_df.main(path,regex)

    #onlyinnew = generate_queries.read_query1to4()
    darwin_json = "Standard_objects.json"
    sag_systems=systems_group.get_systems_ip_list(darwin_json)
    #darwin_transform.json
    #generate_queries.save_new_transform_json(onlyInNew=onlyinnew)
    generate_queries.save_new_transform_json(onlyInNew=sag_systems)
    #upload all_red_networks systems to mysql systems table
    #generate_queries.main()
    generate_queries.systems_to_sql(sag_systems)

    snic_path = "20220630-snic_ip_network_assignments.csv"
    eagle_filter.fill_eagle_from_snic(filepath_qc=snic_path)

    # resolving ip to fqdn for white_apps
    # each time the ip-fqdn pair will be appended to DARWIN_DB->src_dns
    darwin_resolve.resolve_white_apps()

if __name__ == "__main__":
    main()
