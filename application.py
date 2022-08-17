import json
import re
import shutil
from pathlib import Path

import file_operations
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
    # first     run file_operations.py
    # second    run SGRE to unpack se_ruleset, copy here
    ptrn = re.compile("fokus_ruleset_unpacked\d{2}[A-Za-z]{3}\d{4}\.xlsx$")
    newest_rlst = file_operations.search_newest_in_folder(Path("./"), ptrn)
    print("Using " + newest_rlst.resolve().__str__())
    filepath_qc = newest_rlst.resolve().__str__()
    qc_to_sql.main(filepath_qc)

    #mysql db:CSV_DB mysql table:st_ports
    path = "Network-CST-V-SAG-Fokus-CO.json"
    standard_path = "Fokus_AC_Standard_objects.json"
    import_rules.main(path,standard_path)

    filepath_list = []
    file_operations.one_file_found_in_folder(filepath_list=filepath_list,
                                             project_dir=Path("./"),
                                             pttrn_snic=re.compile("\d{4}\d{2}\d{2}-snic_ip_network_assignments.csv"))
    print("%s used to fill mysql tables eagle, snic_export" %filepath_list[0])

    #fill mysql tables eagle, snic_export, run eagle_comparison.sql
    #eagle_filter.main(filepath_list[0])
    #eagle_filter.snic_to_sql(filepath_list[0])

    # new_transform.json
    sag_systems = systems_group.get_systems_ip_list(darwin_json=standard_path)
    generate_queries.save_new_transform_json(onlyInNew=sag_systems)
    generate_queries.systems_to_sql(sag_systems)

    # download hits to hits/...json
    #hits.main()
    # creating 'ip_%Y%m%d' table from 'ip'
    #create_table_old_ip.main("ip" + datetime.datetime.now().strftime("%d%m%y"))
    # .json to mysql table 'ip'
    #path = "/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/fokus_hits/"
    #regex = "^hit.*"
    #bulk_json_to_df.main(path,regex)

    # resolving ip to fqdn for white_apps
    # each time the ip-fqdn pair will be appended to CSV_DB->src_dns
    # resolveIpToName.resolve_white_apps()

if __name__ == "__main__":
    main()
