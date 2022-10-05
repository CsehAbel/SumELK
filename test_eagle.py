import re
from pathlib import Path
from unittest import TestCase

import pandas

import application
import eagle_filter
import file_operations
import qc_to_sql
import systems_group


class TestRegexpMatchRuleName(TestCase):

    def test_file_operations(self):
        file_operations.remove_files_in_dir(
            pttrn=re.compile("se_ruleset_unpacked\d{2}[A-Za-z]{3}\d{4}\.xlsx$"), dir=Path(file_operations.project_dir))
        network = "Network-CST-P-SAG-Energy.json"
        standard = "Standard_objects.json"
        pttrn = re.compile("^Energy_policy.*\.tar\.gz")
        file_operations.remove_files_in_dir(
            pttrn=pttrn, dir=Path(file_operations.project_dir) / "policy")
        file_operations.extract_policy_to_project_dir(pttrn=pttrn,network_file=network,standard_file=standard)

        #remove snic.csv
        pttrn_snic = re.compile("\d{4}\d{2}\d{2}-snic_ip_network_assignments\.csv$")
        file_operations.remove_files_in_project_dir(pttrn_ruleset=pttrn_snic)

        # copy new snic.csv
        localdir = "/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/"
        newest_snic = file_operations.ssh_download.search_newest_in_folder(pttrn=pttrn_snic, policies="/D:/snic/", localdir=localdir)

        snics_found = []
        file_operations.one_file_found_in_folder(filepath_list=snics_found,
                                                 project_dir=Path("./"),
                                                 pttrn_snic=re.compile(
                                                     "\d{4}\d{2}\d{2}-snic_ip_network_assignments.csv"))
        self.assertTrue(snics_found.__len__() == 1)
        # delete hits
        file_operations.delete_hits(dir="hits")
        self.assertTrue([x for x in Path("hits").iterdir()].__len__() == 1)
        # renames new_transform.json
        file_operations.rename_darwin_transform_json()

    #test_eagle_filter
    def test_eagle_filter(self):
        application.use_eagle_filter()

    def test_gen_queries(self):
        standard_path = "Standard_objects.json"
        sag_systems = systems_group.get_systems_ip_list(darwin_json=standard_path)
        application.use_generate_queries(sag_systems)

    def test_import_rules(self):
        row = application.create_table_old_ip.get_row_count(table="st_ports")
        standard_path = "Standard_objects.json"
        application.use_import_rules(standard_path)
        row2 = application.create_table_old_ip.get_row_count(table="st_ports")
        self.assertTrue(row2 != row)

    def test_hits(self):
        standard_path = "Standard_objects.json"
        sag_systems = systems_group.get_systems_ip_list(darwin_json=standard_path)
        # download hits to hits/...json
        path = Path("/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/hits/")
        application.hits.main(path=path, sag_systems=sag_systems)
        # creating 'ip_%Y%m%d' table from 'ip'
        application.create_table_old_ip.main("ip_" + application.datetime.datetime.now().strftime("%Y%m%d"))

    # .json to mysql table 'ip'
    def test_bulk_json_to(self):
        row = application.create_table_old_ip.get_row_count(table="ip")
        path = Path("/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/hits/")
        regex = "^hit_energy.*\.json$"
        application.bulk_json_to_df.main(path, regex)
        row2 = application.create_table_old_ip.get_row_count(table="ip")
        self.assertTrue(row2 != row)


    def test_fill_white_apps_se_ruleset(self):
        row = application.create_table_old_ip.get_row_count(table="white_apps_se_ruleset")
        filepath_qc = application.search_newest_rlst_unpacked()
        qc_to_sql.main(filepath_qc)
        row2 = application.create_table_old_ip.get_row_count(table="white_apps_se_ruleset")
        self.assertTrue(row2 != row)

