import json
import logging
import re
from pathlib import Path
from unittest import TestCase
import file_operations
import import_rules
import systems_group
import main as hits
import create_table_old_ip
import bulk_json_to_df
import datetime
import generate_queries
import eagle_filter
import pandas


class TestRegexpMatchRuleName(TestCase):

    #setup two loggers with different file handlers
    def setup_logger(self, name, log_file, level=logging.INFO):
        """Function setup as many loggers as you want"""

        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))

        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.addHandler(handler)

        return logger

    db_name = "CSV_DB"
    standard_path = "Standard_objects.json"
    network_path = "Network-CST-P-SAG-Energy.json"

    def test_file_operations(self):
        pttrn = re.compile("^Energy_policy.*\.tar\.gz")
        file_operations.remove_files_in_dir(
            pttrn=pttrn, dir=Path(file_operations.project_dir) / "policy")
        policies = '/D:/projects/se/se_cofw_policies/'
        localdir = "/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/policy/"
        file_operations.extract_policy_to_project_dir(pttrn=pttrn,network_file=self.__class__.network_path,standard_file=self.__class__.standard_path,fromHere=policies,toHere=localdir)
        #remove snic.csv
        pttrn_snic = re.compile("\d{4}\d{2}\d{2}-snic_ip_network_assignments\.csv$")
        file_operations.remove_files_in_project_dir(pttrn_ruleset=pttrn_snic)

        # copy new snic.csv
        localdir = "/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/"
        newest_snic = file_operations.ssh_download.download_file(pttrn=pttrn_snic, fromHere="/D:/snic/", toHere=localdir)

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
        source=Path("new_transform.json")
        target_string ="./transform_history/%s_new_transform.json"
        file_operations.rename_darwin_transform_json(source,target_string)

    # test_eagle_filter
    def test_eagle_filter(self):
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
        eagle_filter.dict_to_sql(list_unpacked_ips,self.db_name)
        eagle_filter.snic_to_sql(snics_found[0])

    def test_gen_queries(self):
        # fills systems table with sag_systems exploded into single ips,
        # which is later used for filtering hits on source ips
        sag_systems = systems_group.get_systems_ip_list(darwin_json=self.__class__.standard_path)
        generate_queries.save_new_transform_json(sag_systems=sag_systems,new_name="new_transform.json")
        generate_queries.systems_to_sql(systems=sag_systems,table_name="systems",db_name=self.__class__.db_name)

    def test_import_rules(self):
        logger_insert_fw_policy= self.setup_logger("insert_fw_policy", "logs/insert_fw_policy.log",logging.INFO)
        logger_ip_utils = self.setup_logger("ip_utils", "logs/ip_utils.log",logging.INFO)
        row = create_table_old_ip.get_row_count(table="fwpolicy", db_name=self.__class__.db_name)
        standard_path = "Standard_objects.json"

        list_rules = import_rules.main(self.__class__.network_path, standard_path)
        list_exploded, max_services_length = import_rules.proc_dest_port_tuples(list_rules)

        #write list of dictionaries to json
        with open('policy_dump/fw_policy_nice.json', 'w') as outfile:
            jsonfile = json.dumps(list_exploded, indent=4)  # ,sort_keys=True)
            outfile.write(jsonfile)
        print("fw_policy.json written")

        import_rules.dict_to_sql(list_unpacked_ips=list_exploded , max_services_length=max_services_length, db_name=self.__class__.db_name)
        row2 = create_table_old_ip.get_row_count(table="fwpolicy", db_name=self.__class__.db_name)
        # assert  that logs/insert_fw_policy.log is empty
        self.assertTrue(Path("logs/insert_fw_policy.log").stat().st_size == 0)
        self.assertTrue(row2 != row)

    def test_hits(self):
        # gets the systems ip ranges from darwin_json
        sag_systems = systems_group.get_systems_ip_list(darwin_json=self.__class__.standard_path)
        # download hits to hits/...json
        path = Path("/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/hits/")
        hits.main(path=path, sag_systems=sag_systems)
        # creating 'ip_%Y%m%d' table from 'ip'
        create_table_old_ip.main(history_table="ip_" + datetime.datetime.now().strftime("%Y%m%d"),db_name=self.__class__.db_name)

    # .json to mysql table 'ip'
    def test_bulk_json_to(self):
        row = create_table_old_ip.get_row_count(table="ip", db_name=self.__class__.db_name)
        path = Path("/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/hits/")
        regex = "^hit_energy.*\.json$"
        bulk_json_to_df.main(path, regex, self.db_name)
        row2 = create_table_old_ip.get_row_count(table="ip", db_name=self.__class__.db_name)
        self.assertTrue(row2 != row)