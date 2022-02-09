import datetime
import json
import socket
import struct
import re
from os import listdir
from os.path import isfile, join

lt_date = datetime.datetime(day=23, year=2022, month=1)
duration = datetime.timedelta(days=10)
gt_date = lt_date - duration
print(gt_date.strftime("%Y-%m-%dT%H:%M:%S"))

import pandas as pd


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

def list_files(path):
    pttrn_bckt=re.compile("^hit.*")
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


def create_dataframe(full_path):
# ToDo iterate through files saved created during elastic query
    df_list_per_line=[]
    with open(full_path, "r") as after_key:
        print("create_dataframe: %s" %full_path)
        line=True
        while line:
            line = after_key.readline().strip()
            if line.__len__()==0:
                continue
            df_list_per_line.append(create_df_from_line(line))
            # can be run after while loop, will it save performance?
            #df = df.drop_duplicates()

    df = pd.concat(df_list_per_line, ignore_index=True)
    return df

def main():
    path="/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/hits/"
    lf=list_files(path)
    df_list_per_file=[]
    for f in lf:
        df_list_per_file.append(create_dataframe(join(path, f)))
        print("%s done!" %f)

    file_name="df_hits.csv"
    df=pd.concat(df_list_per_file,ignore_index=True)
    df.to_csv(file_name)
    print("Concatenation done!")


if __name__ == '__main__':
    main()