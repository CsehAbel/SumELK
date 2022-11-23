import math
import re
import socket
import struct
from pathlib import Path
import ip_utils

import pandas
import sqlalchemy
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String

import secrets

def snic_to_sql(filepath_qc):

    attachment_qc = pandas.read_csv(filepath_qc, index_col=None, dtype=str, sep=";")

    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "CSV_DB"), pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    attachment_qc.to_sql("snic_export", dbConnection, if_exists='replace', index=True)

#filter snic_export for only the rows that have eagle service_points,
#collect ip,cidr,sp to upload to eagle mysql table
#collect also
#read_sp_list() -> read service_points.csv into a list
#snic_export is provided as attachment_qc
#for each row in snic_export, check if the service_point is in the list
#pass to unpack_ips the result
def to_unpack_ips_1(attachment_qc, lines):
    pre_list_unpacked_ips = []
    for index, row in attachment_qc.iterrows():
        sp = row["SNX Service Point ID"]
        if not pandas.isna(sp) and type(sp) is str:
            sp = sp.strip()
        if sp in lines:
            b = row["IP-net-base"]
            cidr = row["CIDR"]
            pre_list_unpacked_ips.append({"ip":b,"cidr":int(cidr)})
    return pre_list_unpacked_ips

#filepath_qc is downloaded from snic, contains fields inet-start, inet-stop, supported_by, comment
def to_unpack_ips_2(attachment_qc):
    #regex pattern matching "cloud" case insensitive
    patternCloud = re.compile('.*?cloud.*?', re.IGNORECASE)
    # regex pattern matching "eagle" case insensitive
    patternAzure = re.compile('.*?azure.*?', re.IGNORECASE)
    # regex pattern matching "aws" case insensitive
    patternAws = re.compile('.*?aws.*?', re.IGNORECASE)
    # regex pattern matching "atos" case insensitive
    patternAtos = re.compile('.*?atos.*?', re.IGNORECASE)

    #filter out rows where supported_by matches case patternAtos
    attachment_qc2 = attachment_qc[~attachment_qc["supported_by"].str.match(patternAtos)]
    # keep rows where comment matches case patternCloud, patternAzure, patternAws
    attachment_qc3 = attachment_qc2[attachment_qc2["comment"].str.match(patternCloud) | attachment_qc2["comment"].str.match(patternAzure) | attachment_qc2["comment"].str.match(patternAws)]
    #create a similar list of dictionaries as in to_unpack_ips_1
    #find the ip base and cidr from nic.siemens.net report
    pre_list_unpacked_ips = []
    #csv headers inet_start;inet_stop;supported_by;type;comment
    #for each row in the filtered dataframe select the inet_start, inet_stop, supported_by, comment and create a dictionary
    for index, row in attachment_qc3.iterrows():
        inet_start = row["inet_start"]
        inet_stop = row["inet_stop"]
        #convert inet_start and inet_stop to ip and cidr
        cidr = ip_utils.iprange_to_cidr(inet_start, inet_stop)
        sp = row["supported_by"]
        sp = row["comment"]
        pre_list_unpacked_ips.append({"ip":inet_start,"cidr":cidr})
    return pre_list_unpacked_ips

#ToDo propagate the sp from the snic report to the eagle mysql table
#ToDo propagate the comment, supported_by from the snic report to the eagle mysql table
def unpack_ips(pre_list_unpacked_ips):
    list_unpacked_ips = []
    for d in pre_list_unpacked_ips:
        prefix2 = d["ip"]
        cidr2 = d["cidr"]
        base = integer_to_ipaddress(
            ipaddress_to_integer(prefix2) & cidr_to_integer(cidr2)
        )
        if base != prefix2:
            print("Not a network Adresse (possible ip base %s)" % base)

        int_prefix_top = (~cidr_to_integer(
            cidr2)) | ipaddress_to_integer(prefix2)
        if int_prefix_top - 2 * 32 == -4117887025:
            print("Test singed to unsigned conversion")

        prefix_top = integer_to_ipaddress(int_prefix_top)
        # print("netw.adrr.:{}".format(base))
        for j in range(ipaddress_to_integer(base),
                       ipaddress_to_integer(
                           integer_to_ipaddress(int_prefix_top)) + 1):
            list_unpacked_ips.append({"ip": integer_to_ipaddress(j), "base": base, "cidr": cidr2})
    return list_unpacked_ips

def read_sp_list(service_points_path):
    path = Path(service_points_path);
    # trim the the beginning and end of each line
    # create a list from the lines in the file
    with path.open() as f:
        lines = [line.strip() for line in f]
    return lines

def dict_to_sql(list_unpacked_ips):
        sqlEngine = create_engine(
            'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "CSV_DB"),
            pool_recycle=3600)
        metadata_obj = MetaData()
        eagle_table = drop_and_create_eagle_table(metadata_obj, sqlEngine)

        conn = sqlEngine.connect()

        insert_to_eagle_table(conn, eagle_table,list_unpacked_ips)
        print("eagle insert done!")

def insert_to_eagle_table(conn, table, list_unpacked_ips):
    slices=to_slices(1000,list_unpacked_ips)
    #for each slice of 1000 rows insert into the eagle table
    for s in slices:
        #try to insert the slice into the eagle table
        try:
            conn.execute(table.insert().values(s))
        #if the insert fails print the error
        except Exception as e:
            print(e)

def to_slices(divisor, systems_ips):
    length = len(systems_ips)
    quotient, rest = divmod(length, divisor)
    slices = []  # [[list[0],...list[999]],]
    lower_bound = 0
    for i in range(quotient + 1):
        upper_bound = (i + 1) * divisor
        if upper_bound < length:
            slices.append(systems_ips[slice(lower_bound, upper_bound, 1)])
        else:
            slices.append(systems_ips[slice(lower_bound, length, 1)])
        lower_bound = upper_bound
    return slices

def drop_and_create_eagle_table(metadata_obj, sqlEngine):
        eagle_table = Table('eagle', metadata_obj,
                         Column('id', Integer, primary_key=True),
                         Column('ip', String(15), nullable=False),
                         Column('base', String(15), nullable=False),
                         Column('cidr', Integer, nullable=False)
                         )
        # check first for table existing
        eagle_table.drop(sqlEngine, checkfirst=False)
        eagle_table.create(sqlEngine)
        return eagle_table