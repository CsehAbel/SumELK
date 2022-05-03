import datetime
import json
import socket
import struct
import re
from os import listdir
from os.path import isfile, join
import sys
import shlex
from pathlib import Path
import argparse
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

def get_cli_args():
    parser = argparse.ArgumentParser("Query Elastic Yellow Indices, see --help for options")
    parser.add_argument(
        "--data_dir",
        dest="data_dir",
        type=lambda p: Path(p).absolute(),
        required=True,
        help="Path to the data directory",
    )
    args = parser.parse_args(shlex.split(" ".join(sys.argv[1:])))
    return args

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

def create_dataframe(x,func):
# ToDo iterate through files saved created during elastic query
    df_list_per_line=[]
    with x.open("r",encoding="utf-8") as f:
        print("create_dataframe: %s" %f.name)
        line=True
        while line:
            line = f.readline().strip()
            if line.__len__()==0:
                continue
            df_list_per_line.append(func(line))
            # can be run after while loop, will it save performance?
            #df = df.drop_duplicates()

    df = pd.concat(df_list_per_line, ignore_index=True)
    return df

def main():
    directory=get_cli_args().data_dir
    pttrn_bckt = re.compile(".*\.json")

    df_list_per_file = []
    for x in directory.iterdir():
        if x.is_file() and pttrn_bckt.match(x.name):
            df_list_per_file.append(create_dataframe(x,create_df_from_line))
            print("%s done!" %x.name)
    df=pd.concat(df_list_per_file,ignore_index=True)
    print("Done! number of rows in df: %d" %df.shape[0])

if __name__ == '__main__':
    main()