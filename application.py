import argparse
import datetime
import re
from pathlib import Path
import create_table_old_ip
import file_operations
import generate_queries
import import_rules
import systems_group
import qc_to_sql
import main as hits
import bulk_json_to_df
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

def search_newest_rlst_unpacked():
    ptrn = re.compile("darwin_ruleset_unpacked.\d{2}[A-Za-z]{3}\d{4}\.xlsx$")
    newest_rlst = file_operations.search_newest_in_folder(Path("./"), ptrn)
    print("Using " + newest_rlst.resolve().__str__())
    filepath_qc = newest_rlst.resolve().__str__()
    return filepath_qc

def use_generate_queries(sag_systems):
    generate_queries.save_new_transform_json(sag_systems=sag_systems)
    generate_queries.systems_to_sql(sag_systems)


def use_import_rules(standard_path):
    path = "./Network-CST-P-SAG-Darwin.json"
    import_rules.main(path, standard_path)

def main():
    # first run file_operations.py
    # second run SGRE to unpack se_ruleset, copy here
    filepath_qc = search_newest_rlst_unpacked()
    qc_to_sql.main(filepath_qc)

    standard_path = "Standard_objects.json"
    #mysql db:CSV_DB mysql table:st_ports

    use_import_rules(standard_path)

    # new_transform.json
    sag_systems = systems_group.get_systems_ip_list(darwin_json=standard_path)
    use_generate_queries(sag_systems)

    # download hits to hits/...json
    path = Path("/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/hits/")
    hits.main(path=path,sag_systems=sag_systems)
    # creating 'ip_%Y%m%d' table from 'ip'
    create_table_old_ip.main("ip_" + datetime.datetime.now().strftime("%Y%m%d"))
    # .json to mysql table 'ip'

    regex = "^hit_darwin.*\.json$"
    bulk_json_to_df.main(path,regex)

    # resolving ip to fqdn for white_apps
    # each time the ip-fqdn pair will be appended to DARWIN_DB->src_dns
    #darwin_resolve.resolve_white_apps()

if __name__ == "__main__":
    main()
