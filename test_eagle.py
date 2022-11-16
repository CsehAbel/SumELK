import json
import logging
import re
from pathlib import Path
from unittest import TestCase
import application
import file_operations
import import_rules
import systems_group


class TestRegexpMatchRuleName(TestCase):

    db_name = "DARWIN_DB"

    def test_file_operations(self):
        network = "Network-CST-P-SAG-Darwin.json"
        standard = "Standard_objects.json"
        pttrn = re.compile("^DARWIN_policy.*\.tar\.gz")
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

    def test_gen_queries(self):
        standard_path = "Standard_objects.json"
        # fills systems table with sag_systems exploded into single ips,
        # which is later used for filtering hits on source ips
        sag_systems = systems_group.get_systems_ip_list(darwin_json=standard_path)
        application.use_generate_queries(sag_systems)

    def test_import_rules(self):
        logger_insert_fw_policy= application.setup_logger("insert_fw_policy", "logs/insert_fw_policy.log",logging.INFO)
        logger_ip_utils = application.setup_logger("ip_utils", "logs/ip_utils.log",logging.INFO)
        row = application.create_table_old_ip.get_row_count(table="fwpolicy", db_name=self.__class__.db_name)
        standard_path = "Standard_objects.json"

        path = "Network-CST-P-SAG-Darwin.json"
        list_rules = import_rules.main(path, standard_path)
        list_exploded, max_services_length = import_rules.proc_dest_port_tuples(list_rules)

        #write list of dictionaries to json
        with open('policy_dump/fw_policy_nice.json', 'w') as outfile:
            jsonfile = json.dumps(list_exploded, indent=4)  # ,sort_keys=True)
            outfile.write(jsonfile)
        print("fw_policy.json written")

        import_rules.dict_to_sql(list_unpacked_ips=list_exploded , max_services_length=max_services_length)
        row2 = application.create_table_old_ip.get_row_count(table="fwpolicy", db_name=self.__class__.db_name)
        # assert  that logs/insert_fw_policy.log is empty
        self.assertTrue(Path("logs/insert_fw_policy.log").stat().st_size == 0)
        self.assertTrue(row2 != row)

    def test_hits(self):
        standard_path = "Standard_objects.json"
        # gets the systems ip ranges from darwin_json
        sag_systems = systems_group.get_systems_ip_list(darwin_json=standard_path)
        # download hits to hits/...json
        path = Path("/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/hits/")
        application.hits.main(path=path, sag_systems=sag_systems)
        # creating 'ip_%Y%m%d' table from 'ip'
        application.create_table_old_ip.main(history_table="ip_" + application.datetime.datetime.now().strftime("%Y%m%d"),db_name=self.__class__.db_name)

    # .json to mysql table 'ip'
    def test_bulk_json_to(self):
        row = application.create_table_old_ip.get_row_count(table="ip", db_name=self.__class__.db_name)
        path = Path("/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/hits/")
        regex = "^hit_darwin.*\.json$"
        application.bulk_json_to_df.main(path, regex)
        row2 = application.create_table_old_ip.get_row_count(table="ip", db_name=self.__class__.db_name)
        self.assertTrue(row2 != row)
