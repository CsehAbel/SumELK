import re
from pathlib import Path
from unittest import TestCase

import pandas

import application
import eagle_filter
import file_operations


class TestRegexpMatchRuleName(TestCase):

    #test_eagle_filter
    def test_eagle_filter(self):
        filepath_list = []
        file_operations.one_file_found_in_folder(filepath_list=filepath_list,
                                                 project_dir=Path("./"),
                                                 pttrn_snic=re.compile(
                                                     "\d{4}\d{2}\d{2}-snic_ip_network_assignments.csv"))
        print("%s used to fill mysql tables eagle, snic_export" % filepath_list[0])
        # fill mysql tables eagle, snic_export, run eagle_comparison.sql
        service_points_path = "service_points.csv"
        lines = eagle_filter.read_sp_list(service_points_path)
        self.assertTrue(lines.__len__() > 0)
        attachment_qc = pandas.read_csv(filepath_list[0], index_col=None, dtype=str, sep=";")
        pre_list_unpacked_ips = eagle_filter.get_unpacked_list(attachment_qc, lines)
        self.assertTrue(0<pre_list_unpacked_ips.__len__())
        list_unpacked_ips = eagle_filter.unpack_ips(pre_list_unpacked_ips)
        self.assertTrue(0<list_unpacked_ips.__len__())
        eagle_filter.df_to_sql(list_unpacked_ips)
        eagle_filter.snic_to_sql(filepath_list[0])
