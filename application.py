import datetime
import re
from pathlib import Path

import pandas

import create_table_old_ip
import file_operations
import generate_queries
import import_rules
import systems_group
import qc_to_sql
import main as hits
import bulk_json_to_df
import eagle_filter
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

def use_file_operations():
    ptrn = re.compile("se_ruleset_unpacked.\d{2}[A-Za-z]{3}\d{4}\.xlsx$")
    newest_rlst = file_operations.search_newest_in_folder(Path("./"), ptrn)
    print("Using " + newest_rlst.resolve().__str__())
    filepath_qc = newest_rlst.resolve().__str__()
    return filepath_qc


def use_generate_queries(sag_systems):
    generate_queries.save_new_transform_json(sag_systems=sag_systems)
    generate_queries.systems_to_sql(sag_systems)


def use_import_rules(standard_path):
    path = "./Network-CST-P-SAG-Energy.json"
    import_rules.main(path, standard_path)


def use_eagle_filter():
    service_points_path = "service_points.csv"
    lines = eagle_filter.read_sp_list(service_points_path)
    #create subset of to be unpacked ips
    snics_found = []
    file_operations.one_file_found_in_folder(filepath_list=snics_found,
                                             project_dir=Path("./"),
                                             pttrn_snic=re.compile("\d{4}\d{2}\d{2}-snic_ip_network_assignments.csv"))
    print("%s used to fill mysql tables eagle, snic_export" % snics_found[0])
    attachment_snic = pandas.read_csv(snics_found[0], index_col=None, dtype=str, sep=";")
    pre_list_unpacked_ips1 = eagle_filter.to_unpack_ips_1(attachment_snic, lines)
    list_unpacked_ips1 = eagle_filter.unpack_ips(pre_list_unpacked_ips1)

    # create subset of to be unpacked ips
    network_cont = []
    file_operations.one_file_found_in_folder(filepath_list=network_cont,
                                             project_dir=Path("./"),
                                             pttrn_snic=re.compile("\d{4}\d{2}\d{2}-network_container.csv"))
    print("%s used to fill mysql tables eagle, snic_export" % snics_found[0])
    attachment_network_container = pandas.read_csv(network_cont[0], index_col=None, dtype=str, sep=";")
    pre_list_unpacked_ips2 = eagle_filter.to_unpack_ips_2(attachment_network_container)
    list_unpacked_ips2 = eagle_filter.unpack_ips(pre_list_unpacked_ips2)

    #merge the two list of dictionaries
    list_unpacked_ips = list_unpacked_ips1 + list_unpacked_ips2
    eagle_filter.dict_to_sql(list_unpacked_ips)
    eagle_filter.snic_to_sql(snics_found[0])


def main():
    # first run file_operations.py
    # second run SGRE to unpack se_ruleset, copy here
    filepath_qc = use_file_operations()
    qc_to_sql.main(filepath_qc)

    standard_path = "Standard_objects.json"
    #mysql db:CSV_DB mysql table:st_ports

    use_import_rules(standard_path)

    use_eagle_filter()

    # new_transform.json
    sag_systems = systems_group.get_systems_ip_list(darwin_json=standard_path)
    use_generate_queries(sag_systems)

    # download hits to hits/...json
    path = Path("/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/hits/")
    hits.main(path=path,sag_systems=sag_systems)
    # creating 'ip_%Y%m%d' table from 'ip'
    create_table_old_ip.main("ip_" + datetime.datetime.now().strftime("%Y%m%d"))
    # .json to mysql table 'ip'

    regex = "^hit_energy.*\.json$"
    bulk_json_to_df.main(path,regex)

    # resolving ip to fqdn for white_apps
    # each time the ip-fqdn pair will be appended to CSV_DB->src_dns
    # resolveIpToName.resolve_white_apps()



if __name__ == "__main__":
    main()
