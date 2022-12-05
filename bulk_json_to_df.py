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
import csv
import use_mysql_cursors

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

def list_files(path,regex):
    pttrn_bckt=re.compile(regex)
    onlyfiles = []
    for f in listdir(path):
        if (isfile(join(path, f)) and pttrn_bckt.match(f)):
            onlyfiles.append(f)
    return onlyfiles

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


def main(path, regex,db_name):
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", db_name), pool_recycle=3600)
    metadata_obj = MetaData()
    ip_table = drop_and_create_ip_table(metadata_obj, sqlEngine)

    #conn = sqlEngine.connect()
    # list_files checks for regex ^hit.*
    lf = list_files(path, regex)
    #first merge all the files  into a csv
    #initialize the csv
    lf = list_files(path, regex)
    #C:\ProgramData\MySQL\MySQL Server 8.0\data\Uploads\
    #/mnt/c/ProgramData/MySQL/MySQL Server 8.0/data/Uploads/
    csv_path = Path("/mnt/c/ProgramData/MySQL/MySQL Server 8.0/data/Uploads/ip_dump.csv")
    with csv_path.open('w', newline='') as csvfile:
        spamwriter = csv.writer(csvfile)
        #spamwriter.writerow(["src_ip","dst_ip"])
        count=0
        artificial_index=0
        for f in lf:
            count+=1
            if count==2:
                break
            #for each file, read the file and append to the csv
            full_path = join(path, f)
            path1 = Path(full_path)
            #write absolute path to csv
            with path1.open() as after_key:
                print("write to csv: %s" % path1.absolute().name)
                line = True
                while line:
                    line = after_key.readline().strip()
                    if line.__len__()==0:
                        continue
                    row = json.loads(line)
                    sip = row["source_ip"]
                    dip = row["dest_ip"]
                    spamwriter.writerow([artificial_index,sip,dip])
                    artificial_index+=1
    print("csv done!")
    #path="/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/ip_dump.csv"
    path="C:\\\\ProgramData\\\\MySQL\\\\MySQL Server 8.0\\\\data\\\\Uploads\\\\ip_dump.csv"
    use_mysql_cursors.load_csv_to_mysql(db_name="CSV_DB", path=path, table="ip")
    #table_name="ip"
    #engine_string = 'mysql+pymysql://%s:%s@%s/%s::%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", db_name, table_name)
    #x=odo.odo('ip_dump.csv', engine_string)
    #upload that csv to the database
    #while uploading the csv, add a column with the ip converted to int
    #after done, go to HibernateProject and finish fetching the "ip" table now with the int values as paramete



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
    ip_table.drop(sqlEngine, checkfirst=True)
    ip_table.create(sqlEngine)
    return ip_table

if __name__ == '__main__':
    path = Path("/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/hits/")
    regex = "^hit_energy.*\.json$"
    main(path, regex, "CSV_DB")
