import os

import pandas
import openpyxl
from openpyxl.utils.dataframe import dataframe_to_rows
import re
import socket
import struct
import math


def test_matches(attachment):


    for index, row in attachment.iterrows():


        dict_raw_field = {"app_id": [], "tufin_id": row["Tufin ID"], "ips_field": row["Ips"]}
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

            patternPrefixCIDR = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/(\d+)\s*$')
            resultPrefixCIDR = patternPrefixCIDR.match(i)
            if resultPrefixCIDR:
                inner_matches["cidr"]=True

            patternPrefixRange = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.([0-9]{1,3})-(\d+)\s*$')
            resultPrefixRange = patternPrefixRange.match(i)
            if resultPrefixRange:
                inner_matches["range"]=True

            patternPrefixCommaSeparated = re.compile('^\s*([1-9][0-9]{10,11})\s*$')
            resultPrefixCommaSeparated = patternPrefixCommaSeparated.match(i)
            if resultPrefixCommaSeparated:
                ip_trsfrmd=correctMatchedPrefix(i)
                inner_matches["commaseparated"]=True

            patternBindestrich = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})-([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*$')
            resultBindestrich = patternBindestrich.match(i)
            if resultBindestrich:
                inner_matches["bindestrich"] = True
                start_ip_b=resultBindestrich.group(1)
                end_ip_b=resultBindestrich.group(2)
                #ToDo resultBindestrich.group(1), group(2)
                #ToDo if group(1) < 0: group(1)=group(1) + 2**32
                #ToDo for i in  range(quadToInt(group(1)),quadToInt(group(2))+1)

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



def get_processed_qc_as_list(attachment_qc):

    test_matches(attachment_qc)
    # use for capturing ip,ip/mask,ip.ip.ip.ip-ip
    list_dict_transformed = []
    for index, row in attachment_qc.iterrows():
        dict_raw_field = {"app_id": row["APP ID"], "tufin_id": row["Tufin ID"], "ips_field": row["Ips"]}
        # dict_raw_field["app_id"],dict_raw_field["tufin_id"],dict_raw_field["ips_field"]

        field = dict_raw_field["ips_field"]
        field_list = []

        list_unpacked_ips = []

        if (not pandas.isnull(field)) and field.find(";") != -1:
            field_list = field.split(";")
        elif (not pandas.isnull(field)) and field.find("\n") != -1:
            field_list = field.split("\n")
        elif (not pandas.isnull(field)):
            field = field.strip(u'\u200b')
            patternPrefix = re.compile('^\s*(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))\s*$')
            resultPrefix = patternPrefix.match(field)
            if resultPrefix:
                prefix = resultPrefix.group(1)
                list_unpacked_ips.append(prefix)

        if len(field_list)==1:
            print("!!!field_list==1")





        for i in field_list:
            i = i.strip(u'\u200b')

            patternPrefix = re.compile('^\s*(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))\s*$')
            resultPrefix = patternPrefix.match(i)
            if resultPrefix:
                prefix = resultPrefix.group(1)
                list_unpacked_ips.append(prefix)

            patternPrefixCIDR = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/(\d+)\s*$')
            resultPrefixCIDR = patternPrefixCIDR.match(i)
            if resultPrefixCIDR:
                prefix2 = resultPrefixCIDR.group(1)
                cidr2 = correctAndCheckMatchedMask(resultPrefixCIDR.group(2))

                base = integerToDecimalDottedQuad(
                    decimalDottedQuadToInteger(prefix2) & makeIntegerMask(
                        cidr2))
                if base != prefix2:
                    print("Not a network Adresse (possible ip base %s)" % base)

                int_prefix_top = (~makeIntegerMask(
                    cidr2)) | decimalDottedQuadToInteger(prefix2)
                if int_prefix_top - 2 * 32 == -4117887025:
                    print("Test singed to unsigned conversion")
                    # ToDo breakpoint setzen, Werte die die for Schleife ausspuckt mit den erwarteten Ergebnisse zu vergleichen
                    # Modified
                    #    decimalDottedQuadToInteger()
                    # to convert signed integers to unsigned.
                    # Das Folgende ist redundant, überreichlich, ersetzt:
                    #   int_prefix_top == -4117887025:
                    #   if int_prefix_top < 0:
                    #      int_prefix_top = int_prefix_top + (2**32)

                prefix_top = integerToDecimalDottedQuad(int_prefix_top)
                print("netw.adrr.:{}".format(base))
                for j in range(decimalDottedQuadToInteger(base) + 1,
                               decimalDottedQuadToInteger(
                                       integerToDecimalDottedQuad(int_prefix_top)) + 1):
                    list_unpacked_ips.append(integerToDecimalDottedQuad(j))

            patternPrefixRange = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.([0-9]{1,3})-(\d+)\s*$')
            resultPrefixRange = patternPrefixRange.match(i)
            if resultPrefixRange:
                prefix3 = resultPrefixRange.group(1)
                fourthoctet3 = resultPrefixRange.group(2)
                fifthoctet3 = resultPrefixRange.group(3)

                start_ip = ".".join([prefix3, fourthoctet3])
                end_ip = ".".join([prefix3, fifthoctet3])
                for j in range(decimalDottedQuadToInteger(start_ip) + 1,
                               decimalDottedQuadToInteger(end_ip) + 1):
                    list_unpacked_ips.append(integerToDecimalDottedQuad(j))

            patternPrefixCommaSeparated = re.compile('^\s*([1-9][0-9]{10,11})\s*$')
            resultPrefixCommaSeparated = patternPrefixCommaSeparated.match(i)
            if resultPrefixCommaSeparated:
                ip_trsfrmd = correctMatchedPrefix(i)
                list_unpacked_ips.append(ip_trsfrmd)

            patternBindestrich = re.compile(
                '^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})-([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*$')
            resultBindestrich = patternBindestrich.match(i)
            if resultBindestrich:
                start_ip_b = resultBindestrich.group(1)
                end_ip_b = resultBindestrich.group(2)
                for j in range(decimalDottedQuadToInteger(start_ip_b),
                               decimalDottedQuadToInteger(start_ip_b) + 1):
                    list_unpacked_ips.append(integerToDecimalDottedQuad(j))

        for element in list_unpacked_ips:
            list_dict_transformed.append(
                #{"app_id": dict_raw_field["app_id"], "tufin_id": dict_raw_field["tufin_id"], "ip": element, "excel_row_line": (index + 2)}
                {"ip": element,"ACP #":row['ACP #'],"APP ID":row['APP ID'],"Tufin ID":row['Tufin ID'],"Source":row['Source'],"Ips":row['Ips'],"Protocol type port":row['Protocol type port'],"FQDNs":row['FQDNs'],"TSA":row['TSA'],"new TSA?":row['new TSA?'],"Application Name":row['Application Name'],"Application Manager\'s mail":row['Application Manager\'s mail'],"Status":row['Status']})

    return list_dict_transformed


def main():
    filepath_qc = "QualityCheckFinal (1).xlsx"
    if os.path.exists(filepath_qc):
        qc = pandas.read_excel(filepath_qc, sheet_name=None,
                               index_col=None, engine='openpyxl')
    else:
        raise FileNotFoundError(filepath_qc)

    attachment_qc = pandas.read_excel(filepath_qc, index_col=None, dtype=str, engine='openpyxl')

    df_qc = pandas.DataFrame(get_processed_qc_as_list(attachment_qc))