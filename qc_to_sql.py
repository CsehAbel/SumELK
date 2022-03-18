import os

import numpy
import numpy as np
import pandas
import openpyxl
from openpyxl.utils.dataframe import dataframe_to_rows
import re
import socket
import struct
import math
from sqlalchemy import create_engine
import secrets

def test_matches(attachment):


    for index, row in attachment.iterrows():


        dict_raw_field = {"app_id": [], "tufin_id": row["Tufin ID"], "ips_field": row["IPs"]}
        # dict_raw_field["app_id"],dict_raw_field["tufin_id"],dict_raw_field["ips_field"]
        field = dict_raw_field["ips_field"]
        field_list=[]
        if (not pandas.isnull(field)) and field.find(";") != -1:
            field_list = field.split(";")
        elif (not pandas.isnull(field)) and field.find("\n") != -1:
            field_list = field.split("\n")

        for i in field_list:
            i=i.strip(u'\u200b')

            inner_matches = {"single": False, "cidr": False, "range": False, "commaseparated":False, "bindestrich":False}

            patternPrefix = re.compile('^\s*(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))\s*$')
            resultPrefix = patternPrefix.match(i)
            if resultPrefix:
                inner_matches["single"]=True

            if not any(inner_matches.values()) and not (i.find("Same as the App") != -1) and not len(i)==0 :
                print("no regex match for 'field'{}".format(i))

            numberofmatches=0
            for m in inner_matches.values():
                if m:
                    numberofmatches+=1
            if numberofmatches > 1:
                print("too many regex matches")



def integerToDecimalDottedQuad(ip_int):
  return (str( (0xff000000 & ip_int) >> 24)   + '.' +
          str( (0x00ff0000 & ip_int) >> 16)   + '.' +
          str( (0x0000ff00 & ip_int) >> 8)    + '.' +
          str( (0x000000ff & ip_int)))

def decimalDottedQuadToInteger(dottedquad):
    #convert decimal dotted quad string to long integer"
    #@ is native, ! is big-endian, native didnt work" \
    #returned the octects reversed main.integerToDecimalDottedQuad(main.decimalDottedQuadToInteger('149.246.14.224'))"
    ip_as_int = struct.unpack('!i', socket.inet_aton(dottedquad))[0]
    if ip_as_int < 0:
        ip_as_int=ip_as_int + 2**32
    return ip_as_int

def makeIntegerMask(cidr):
    #return a mask of n bits as a long integer
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return mask


def correctAndCheckMatchedMask(cidr):
    patternMask = re.compile('[^\d]*(\d+)[^\d]*$')
    resultMask = patternMask.match(cidr)
    mask = resultMask.group(1)
    mask = int(mask)
    return mask

def correctMatchedPrefix(ipaddr):

    patternPrefixCommaSeparated = re.compile('^\s*([1-9][0-9]{10,11})\s*$')
    resultPrefixCommaSeparated = patternPrefixCommaSeparated.match(ipaddr)

    if resultPrefixCommaSeparated:
        digits = [int(x) for x in str(resultPrefixCommaSeparated.group(1))]
        l=len(digits)
        fourthoctet  = [digits[l-3]*100, digits[l-2]*10, digits[l-1]]
        thirdoctet = [digits[l-x]*math.pow(10, x-4)  for x in range(6, 3, -1)]
        secondoctet  = [digits[l-x]*math.pow(10, x-7) for x in range(9, 6, -1)]
        firstoctet = [digits[l-x]*math.pow(10, x-10) for x in range(l, 9, -1)]
        ip = ".".join([str(int(sum(firstoctet))),str(int(sum(secondoctet))),str(int(sum(thirdoctet))),str(int(sum(fourthoctet)))])
        return ip

def match_ip_fqdn(attachment_qc):

    test_matches(attachment_qc)
    # use for capturing ip,ip/mask,ip.ip.ip.ip-ip
    list_index = []

    list_ports = []
    list_fqdns=[]
    for index, row in attachment_qc.iterrows():

        field = row["IPs"]

        field = field.strip(u'\u200b')
        patternPrefix = re.compile('^\s*(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))\s*$')
        resultPrefix = patternPrefix.match(field)
        if resultPrefix:
            prefix = resultPrefix.group(1)
        else:
            continue

        try:
            fqdn=test_fqdn(row["FQDNs"])
        except ValueError as e:
            fqdn=numpy.nan
            print("%dFQDNs error: %s" %(index,row["FQDNs"]))

        list_fqdns.append(fqdn)
        list_index.append(index)

    return list_index,list_fqdns

def match_fqdn_strict(attachment_qc):
    # use for capturing ip,ip/mask,ip.ip.ip.ip-ip
    list_index = []

    list_ports = []
    list_fqdns = []
    for index, row in attachment_qc.iterrows():

        field = row["IPs"]

        field = field.strip(u'\u200b')
        patternPrefix = re.compile('^\s*(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))\s*$')
        resultPrefix = patternPrefix.match(field)
        if resultPrefix:
            prefix = resultPrefix.group(1)
        else:
            continue

        if not pandas.isnull(row["dns2"]):
            fqdn = row["dns2"]
        elif not pandas.isnull(row["FQDN"]):
            fqdn = row["FQDN"]
        else:
            continue

        list_fqdns.append(fqdn)
        list_index.append(index)

    return list_index, list_fqdns

def test_port_field(field):

    list_ports=[]
    field_list=[]
    if (not pandas.isnull(field)) and field.find(";") != -1:
        field_list = field.split(";")

    elif (not pandas.isnull(field)) and field.find("\n") != -1:
        field_list = field.split("\n")

    elif (not pandas.isnull(field)):
        field = field.strip(u'\u200b')
        field_list = [field]

    try:
        for f in field_list:
            list_ports.append(result_per_field(f))
    except ValueError as e:
        raise ValueError(f)

    return ", ".join(list_ports)

def test_fqdn(field):
    if pandas.isnull(field):
        raise ValueError("field is null")

    pattern1=re.compile("\s*http://([^/\s]+\.[a-z]+)",re.IGNORECASE)
    pattern2=re.compile("\s*https://([^/\s]+\.[a-z]+)",re.IGNORECASE)
    pattern3=re.compile("\s*([^/\s]+\.[a-z]+)",re.IGNORECASE)
    result1=pattern1.match(field)
    result2=pattern2.match(field)
    result3=pattern3.match(field)

    if result2:
        fqdn=result2.group(1)
    elif result1:
        fqdn=result1.group(1)
    elif result3:
        fqdn=result3.group(1)
    else:
        raise ValueError()
    return fqdn

def result_per_field(field):
    field = field.strip()
    field = field.strip(u'\u200b')
    patternPrefix1 = re.compile('^(TCP).*?([0-9]+)$',re.IGNORECASE)
    resultPrefix1 = patternPrefix1.match(field)
    patternPrefix2 = re.compile('^(UDP).*?([0-9]+)$', re.IGNORECASE)
    resultPrefix2 = patternPrefix2.match(field)
    patternPrefix3 = re.compile('^(UDP).*?([0-9]+-[0-9]+)$', re.IGNORECASE)
    resultPrefix3 = patternPrefix3.match(field)
    patternPrefix4 = re.compile('^(TCP).*?([0-9]+-[0-9]+)$', re.IGNORECASE)
    resultPrefix4 = patternPrefix4.match(field)
    if resultPrefix1:
        proto = "tcp"
        number = resultPrefix1.group(2)
        return "%s/%s" % (number, proto)
    elif resultPrefix2:
        proto = "udp"
        number = resultPrefix2.group(2)
        return "%s/%s" % (number, proto)
    elif resultPrefix3:
        proto = "udp"
        number = resultPrefix3.group(2)
        return "%s/%s" % (number, proto)
    elif resultPrefix4:
        proto = "tcp"
        number = resultPrefix4.group(2)
        return "%s/%s" % (number, proto)
    else:
        raise ValueError()

def main():
    filepath_qc = "se_ruleset_unpacked18Mar2022.xlsx"
    if os.path.exists(filepath_qc):
        qc = pandas.read_excel(filepath_qc, sheet_name=None,
                               index_col=None, engine='openpyxl')
    else:
        raise FileNotFoundError(filepath_qc)

    attachment_qc = pandas.read_excel(filepath_qc, index_col=None, dtype=str, engine='openpyxl')
    print("attachment_qc.shape[0]=%d" %attachment_qc.shape[0])
    #one column for fqdn = FQDNs, incorrect format set to NaN
    correct_indexes,correct_fqdns = match_ip_fqdn(attachment_qc)
    df_qc=attachment_qc.iloc[correct_indexes]
    #df_qc.insert(0,"Ports",correct_ports,allow_duplicates=False)
    print("df_qc.shape[0]=%d" %df_qc.shape[0])
    df_qc.insert(0,"FQDN", correct_fqdns,allow_duplicates=False)

    #file = "sysdb_2022-02-07.gz"
    #df_sysdb = pandas.read_csv(file, sep=';', encoding="utf-8", dtype='str')
    #df_sysdb = df_sysdb[["ip", "dns"]]
    #df_qc = pandas.merge(left=df_qc, right=df_sysdb, left_on="IPs", right_on="ip", how="left")

    #df_qc["dns2"] = df_qc.apply(lambda x: x["dns"] if x["dns"] != "-" else numpy.nan, axis=1)

    #print("merged df_qc.shape[0]=%d" % df_qc.shape[0])
    #two column for fqdn = FQDNs,dns2 NaN thrown away
    #correct_indexes_2, correct_fqdns_2 = match_fqdn_strict(df_qc)
    #df_qc_fqdn = df_qc.iloc[correct_indexes_2][["IPs","APP ID","Protocol type port","Application Name","FQDN","dns2"]]

    #df_qc_fqdn.insert(0, "FQDN2", correct_fqdns_2, allow_duplicates=False)

    #print("df_qc_fqdn.shape[0]=%d" %df_qc_fqdn.shape[0])
    #df_qc_null = df_qc[ pandas.isnull(df_qc["dns2"]) & pandas.isnull(df_qc["FQDN"])]
    #print("df_qc_null.shape[0]=%d" % df_qc_null.shape[0])
    #df_qc_null = df_qc[~(pandas.isnull(df_qc["FQDN"]))]
    #ToDo send dictionary to Claus
    #ToDo df_qc replace Protocol Type port with ####/tcp
    #ToDo clean up ip ranges, clean up port fields
    #ToDo FQDN remove https,http
    #ToDo df_qc.to_sql()
    sqlEngine = create_engine('mysql+pymysql://%s:%s@%s/%s' %(secrets.mysql_u,secrets.mysql_pw,"127.0.0.1","CSV_DB"), pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    df_qc.to_sql("white_apps_se_ruleset", dbConnection,if_exists='replace', index=True)
    #df_qc_null.to_sql("se_ruleset_fqdn_error", dbConnection, if_exists='replace', index=True)
    print("lel")

if __name__=="__main__":
    main()