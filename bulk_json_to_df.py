import datetime
import json
import socket
import struct
import re
from os import listdir
from os.path import isfile, join
from pathlib import Path

import pandas as pd

import mysql.connector
import sqlalchemy
from mysql.connector import errorcode

from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, UniqueConstraint
import secrets

lt_date = datetime.datetime(day=23, year=2022, month=1)
duration = datetime.timedelta(days=10)
gt_date = lt_date - duration
print(gt_date.strftime("%Y-%m-%dT%H:%M:%S"))

# ToDo customzie databse value for each branch
config = {
    'user': secrets.mysql_u,
    'password': secrets.mysql_pw,
    'host': '127.0.0.1',
    'database': 'CSV_DB',
    'raise_on_warnings': True,
    'allow_local_infile': True
}


def usedb(cursor, DB_NAME):
    try:
        cursor.execute("USE {}".format(DB_NAME))
    except mysql.connector.Error as err:
        print("Database {} does not exists.".format(DB_NAME))
        if err.errno == errorcode.ER_BAD_DB_ERROR:
            print(err)
            exit(1)
        else:
            print(err)
            exit(1)


def integerToDecimalDottedQuad(ip_int):
    return (str((0xff000000 & ip_int) >> 24) + '.' +
            str((0x00ff0000 & ip_int) >> 16) + '.' +
            str((0x0000ff00 & ip_int) >> 8) + '.' +
            str((0x000000ff & ip_int)))


def decimalDottedQuadToInteger(dottedquad):
    # convert decimal dotted quad string to long integer"
    # @ is native, ! is big-endian, native didnt work" \
    # returned the octects reversed main.integerToDecimalDottedQuad(main.decimalDottedQuadToInteger('149.246.14.224'))"
    ip_as_int = struct.unpack('!i', socket.inet_aton(dottedquad))[0]
    if ip_as_int < 0:
        ip_as_int = ip_as_int + 2 ** 32
    return ip_as_int


def list_files(path,regex):
    pttrn_bckt=re.compile(regex)
    onlyfiles = []
    for f in listdir(path):
        if (isfile(join(path, f)) and pttrn_bckt.match(f)):
            onlyfiles.append(f)
    return onlyfiles


def create_df_from_line(line):
    dict_line = json.loads(line)
    # src_ip
    key0 = [key for key, value in dict_line.items()][0]
    # dest_ip
    key1 = [key for key, value in dict_line.items()][1]

    # Can be used to save performance, not sure about 1-to-1 ip-int conversion,
    # if not 1-to-1 it will be visible on the list of values of dest_ips after group by
    # int_key0 = decimalDottedQuadToInteger(dict_line[key0])
    # int_key1 = decimalDottedQuadToInteger(dict_line[key1])
    # index = pd.MultiIndex.from_tuples([(int_key0, int_key1)])

    index = pd.MultiIndex.from_tuples([(dict_line[key0], dict_line[key1])])
    df = pd.DataFrame(dict_line, index=index)
    return df


def create_dataframe(full_path, func):
    # ToDo iterate through files saved created during elastic query
    df_list_per_line = []
    path = Path(full_path)
    with path.open() as after_key:
        print("create_dataframe: %s" % full_path)
        line = True
        while line:
            line = after_key.readline().strip()
            if line.__len__()==0:
                continue
            df_list_per_line.append(func(line))
            # can be run after while loop, will it save performance?
            #df = df.drop_duplicates()
    try:
        df = pd.concat(df_list_per_line, ignore_index=True)
    except ValueError as v:
        print("Anhalten!")

    return df


def main(path, regex):
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "CSV_DB"), pool_recycle=3600)
    metadata_obj = MetaData()
    ip_table = drop_and_create_ip_table(metadata_obj, sqlEngine)

    conn = sqlEngine.connect()
    # list_files checks for regex ^hit.*
    lf = list_files(path, regex)
    for f in lf:
        insert_to_ip_table(conn, f, ip_table, path)
        print("%s done!" % f)


def insert_to_ip_table(conn, f, ip_table, path):
    full_path = join(path, f)
    # ToDo iterate through files saved created during elastic query
    df_list_per_line = []
    path1 = Path(full_path)
    with path1.open() as after_key:
        print("create_dataframe: %s" % full_path)
        line = True
        while line:
            line = after_key.readline().strip()
            if line.__len__()==0:
                continue
            row = json.loads(line)
            sip = row["source_ip"]
            dip = row["dest_ip"]
            ins = ip_table.insert()
            try:
                conn.execute(ins, {"src_ip": sip, "dst_ip": dip})
            except sqlalchemy.exc.IntegrityError as ie:
                print("Insert Error: %s" % line)

    return path1


def drop_and_create_ip_table(metadata_obj, sqlEngine):
    ip_table = Table('ip', metadata_obj,
                     Column('id', Integer, primary_key=True),
                     Column('src_ip', String(15), nullable=False),
                     Column('dst_ip', String(15), nullable=False),
                     UniqueConstraint('src_ip', 'dst_ip', name='my_uniq_id')
                     )
    # check first for table existing
    ip_table.drop(sqlEngine, checkfirst=False)
    ip_table.create(sqlEngine)
    return ip_table


if __name__ == '__main__':
    path = "/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/hits/"
    regex = "^hit.*"
    main(path, regex)
