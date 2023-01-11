import json
import logging
import re
from pathlib import Path
from unittest import TestCase
import file_operations
import ssh_download
import import_rules
import import_hosts
import systems_group
import main as hits
import use_mysql_cursors
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
    standard_path = "temporary/Standard_objects.json"
    network_path = "temporary/Network-CST-P-SAG-Energy.json"

    def test_file_operations(self):
        n = "Network-CST-P-SAG-Energy.json"
        st = "Standard_objects.json"
        pt = re.compile("^Energy_policy.*\.tar\.gz")
        temporary="/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/temporary/"
        file_operations.remove_files_in_dir(
            pttrn=re.compile("^((?!gitkeep).)*$"), dir=Path(temporary))
        fh = '/D:/projects/se/se_cofw_policies/'
        #check if temp folder is empty
        #use the generator to get the number of files in the folder
        sizeOfGenerator = sum(1 for _ in Path(temporary).iterdir())
        self.assertTrue(sizeOfGenerator == 1)
        newest_tar_gz = ssh_download.download_file(pttrn=pt,fromHere=fh,toHere=temporary)
        file_operations.extract_tarinfo(Path(newest_tar_gz),n,st,temporary)
    
        #remove snic.csv
        pttrn_snic = re.compile("\d{4}\d{2}\d{2}-snic_ip_network_assignments\.csv$")
        file_operations.remove_files_in_dir(pttrn=pttrn_snic,dir=Path(temporary))

        newest_snic = file_operations.ssh_download.download_file(pttrn=pttrn_snic, fromHere="/D:/snic/", toHere=temporary)

        snics_found = []
        file_operations.one_file_found_in_folder(filepath_list=snics_found,
                                                 dir=Path(temporary),
                                                 pttrn_snic=re.compile(
                                                     "\d{4}\d{2}\d{2}-snic_ip_network_assignments.csv"))
        self.assertTrue(snics_found.__len__() == 1)
        # renames new_transform.json
        source=Path("new_transform.json")
        target_string ="./transform_history/%s_new_transform.json"
        file_operations.rename_darwin_transform_json(source,target_string)

    # test_eagle_filter
    def test_eagle_filter(self):
        temporary="/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/temporary/"
        temporary_eagle="/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/temporary_eagle/"

        lines_found = []
        file_operations.one_file_found_in_folder(lines_found,
                                                Path(temporary_eagle),
                                                re.compile("service_points.csv"))
        lines = eagle_filter.read_sp_list(lines_found[0])
        #create subset of to be unpacked ips
        snics_found = []
        file_operations.one_file_found_in_folder(snics_found,
                                                Path(temporary),
                                                re.compile("\d{4}\d{2}\d{2}-snic_ip_network_assignments.csv"))
        print("%s used to fill mysql tables eagle, snic_export" % snics_found[0])
        attachment_snic = pandas.read_csv(snics_found[0], index_col=None, dtype=str, sep=";")
        pre_list_unpacked_ips1 = eagle_filter.to_unpack_ips_1(attachment_snic, lines)
        list_unpacked_ips1 = eagle_filter.unpack_ips(pre_list_unpacked_ips1)

        # create subset of to be unpacked ips
        network_cont = []
        file_operations.one_file_found_in_folder(network_cont,
                                                Path(temporary_eagle),
                                                re.compile("\d{4}\d{2}\d{2}-network_container.csv"))
        print("%s used to fill mysql tables eagle, snic_export" % network_cont[0])
        attachment_network_container = pandas.read_csv(network_cont[0], index_col=None, dtype=str, sep=";")
        pre_list_unpacked_ips2 = eagle_filter.to_unpack_ips_2(attachment_network_container)
        list_unpacked_ips2 = eagle_filter.unpack_ips(pre_list_unpacked_ips2)

        #merge the two list of dictionaries
        list_unpacked_ips = list_unpacked_ips1 + list_unpacked_ips2
        row1 = use_mysql_cursors.get_row_count(table="eagle", db_name=self.__class__.db_name)
        eagle_filter.dict_to_sql(list_unpacked_ips,self.db_name)
        row2 = use_mysql_cursors.get_row_count(table="eagle", db_name=self.__class__.db_name)
        self.assertTrue(row2 != row1)
        eagle_filter.snic_to_sql(snics_found[0])

    def test_systems_to_sql(self):
        standard_path = self.__class__.standard_path
        # fills systems table with sag_systems exploded into single ips,
        # which is later used for filtering hits on source ips
        sag_systems = systems_group.get_systems_ip_list(darwin_json=self.__class__.standard_path)
        generate_queries.save_new_transform_json(sag_systems=sag_systems,new_name="new_transform.json")
        generate_queries.systems_to_sql(systems=sag_systems,table_name="systems",db_name=self.__class__.db_name)

    def test_import_rules(self):
        pttrn_logs = re.compile("^.*\.log$")
        file_operations.remove_files_in_dir(pttrn_logs,Path("./logs"))
        logger_insert_fw_policy= self.setup_logger("insert_fw_policy", "logs/insert_fw_policy.log",logging.INFO)
        logger_ip_utils = self.setup_logger("ip_utils", "logs/ip_utils.log",logging.INFO)
        row = use_mysql_cursors.get_row_count(table="fwpolicy", db_name=self.__class__.db_name)
        list_rules = import_rules.main(self.__class__.network_path, self.__class__.standard_path)
        list_exploded, max_services_length = import_rules.proc_dest_port_tuples(list_rules)

        #write list of dictionaries to json
        with open('policy_dump/fw_policy_nice.json', 'w') as outfile:
            jsonfile = json.dumps(list_exploded, indent=4)  # ,sort_keys=True)
            outfile.write(jsonfile)
        print("fw_policy.json written")

        import_rules.dict_to_sql(list_unpacked_ips=list_exploded , max_services_length=max_services_length, db_name=self.__class__.db_name)
        row2 = use_mysql_cursors.get_row_count(table="fwpolicy", db_name=self.__class__.db_name)
        # assert  that logs/insert_fw_policy.log is empty
        self.assertTrue(Path("logs/insert_fw_policy.log").stat().st_size == 0)
        self.assertTrue(row2 != row)

    def test_import_hosts(self):
        pttrn_logs = re.compile("^.*\.log$")
        file_operations.remove_files_in_dir(pttrn_logs,Path("./logs"))
        logger_insert_fw_policy= self.setup_logger("insert_hosts", "logs/insert_hosts.log",logging.INFO)
        logger_ip_utils = self.setup_logger("ip_utils", "logs/ip_utils.log",logging.INFO)
        row = use_mysql_cursors.get_row_count(table="hosts", db_name=self.__class__.db_name)

        list_rules = import_hosts.main(self.__class__.network_path, self.__class__.standard_path)
        import_hosts.dict_to_sql(list_unpacked_ips=list_rules, db_name=self.__class__.db_name)
        
        row2 = use_mysql_cursors.get_row_count(table="hosts", db_name=self.__class__.db_name)
        self.assertTrue(row2 != row)


    def test_hits(self):
        # delete hits
        file_operations.delete_hits(dir=Path("hits"))
        self.assertTrue([x for x in Path("hits").iterdir()].__len__() == 1)
        # gets the systems ip ranges from darwin_json
        sag_systems = systems_group.get_systems_ip_list(darwin_json=self.__class__.standard_path)
        # download hits to hits/...json
        path = Path("/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/hits/")
        hits.main(path=path, sag_systems=sag_systems)
        # creating 'ip_%Y%m%d' table from 'ip'
        use_mysql_cursors.main(history_table="ip_" + datetime.datetime.now().strftime("%Y%m%d"),db_name=self.__class__.db_name)

    # .json to mysql table 'ip'
    def test_bulk_json_to(self):
        row = use_mysql_cursors.get_row_count(table="ip", db_name=self.__class__.db_name)
        path = Path("/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/hits/")
        regex = "^hit_energy.*\.json$"
        csv_path_string = "/mnt/c/ProgramData/MySQL/MySQL Server 8.0/Data/Uploads/ip_dump.csv"
        bulk_json_to_df.main(path, regex, self.__class__.db_name, csv_path_string)
        #ToDo: go to MysqlWorkbench and do LOAD DATA LOCAL INFILE 'ip_dump.csv' INTO TABLE ip FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\r\n' IGNORE 1 LINES;
        row2 = use_mysql_cursors.get_row_count(table="ip", db_name=self.__class__.db_name)
        self.assertTrue(row2 != row)