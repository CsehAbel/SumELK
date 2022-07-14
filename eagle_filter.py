import math
import re
import socket
import struct

import pandas
from sqlalchemy import create_engine

import secrets

def cidr_to_netmask(cidr):
  cidr = int(cidr)
  mask = (0xffffffff >> (32 - cidr)) << (32 - cidr) # wenn cidr=24, 32-cidr = 8
  #0xffffffff >> 8 = int("0000 0000 1111 1111 1111 1111 1111 1111")
  #0xffffff << 8 ->  int("0000 0000 1111 1111 1111 1111 1111 1111") << 8 = int("1111 1111 1111 1111 1111 1111 0000 0000")
  #int("0000 0000 1111 1111 1111 1111 1111 1111") << 8 = ˜int("0000 0000 1111 1111 1111 1111 1111 1111")=int("1111 1111 1111 1111 1111 1111 0000 0000")
  #~x
  #Returns the complement of x - the number you get by switching each 1 for a 0 and each 0 for a 1
  return integerToDecimalDottedQuad(mask)

def netmask_to_cidr(netmask):
    '''
    :param netmask: netmask ip addr (eg: 255.255.255.0)
    :return: equivalent cidr number to given netmask ip (eg: 24)
    '''
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def integerToDecimalDottedQuad(ip_int):
  return (str( (0xff000000 & ip_int) >> 24)   + '.' +
          str( (0x00ff0000 & ip_int) >> 16)   + '.' +
          str( (0x0000ff00 & ip_int) >> 8)    + '.' +
          str( (0x000000ff & ip_int)))

def makeIntegerMask(cidr):
    #return a mask of n bits as a long integer
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return mask

def decimalDottedQuadToInteger(dottedquad):
    #convert decimal dotted quad string to long integer"
    #@ is native, ! is big-endian, native didnt work" \
    #returned the octects reversed main.integerToDecimalDottedQuad(main.decimalDottedQuadToInteger('149.246.14.224'))"
    ip_as_int = struct.unpack('!i', socket.inet_aton(dottedquad))[0]
    if ip_as_int < 0:
        ip_as_int=ip_as_int + 2**32
    return ip_as_int

def old_decimalDottedQuadToInteger(dottedquad):
    #convert decimal dotted quad string to long integer"
    #@ is native, ! is big-endian, native didnt work" \
    #returned the octects reversed main.integerToDecimalDottedQuad(main.decimalDottedQuadToInteger('149.246.14.224'))"
    return struct.unpack('!i', socket.inet_aton(dottedquad))[0]


def isIntegerAddressInIntegerNetwork(ip,net):
   #Is an address in a network"
   return ip & net == net

def isPrefix(ipaddr):
    patternPrefix = re.compile('.*?([0-9]{1,3}[^\d]+[0-9]{1,3}[^\d]+[0-9]{1,3}[^\d]+[0-9]{1,3}).*$')
    resultPrefix = patternPrefix.match(ipaddr)
    #first digit that it starts with is [1-9]
    patternPrefixCommaSeparated = re.compile('[^\d]*?([1-9][0-9]{10,11}).*$')
    resultPrefixCommaSeparated = patternPrefixCommaSeparated.match(ipaddr)
    if resultPrefix or resultPrefixCommaSeparated:
        return True
    else:
        return False

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

def correctAndCheckMatchedMask(cidr):
    patternMask = re.compile('[^\d]*(\d+)[^\d]*$')
    resultMask = patternMask.match(cidr)
    mask = resultMask.group(1)
    mask = int(mask)
    return mask

def snic_to_sql(filepath_qc):

    attachment_qc = pandas.read_csv(filepath_qc, index_col=None, dtype=str, sep=";")

    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "DARWIN_DB"), pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    attachment_qc.to_sql("snic_export", dbConnection, if_exists='replace', index=True)

def main(filepath_qc):

    attachment_qc = pandas.read_csv(filepath_qc, index_col=None, dtype=str, sep=";")

    list_unpacked_ips=[]
    for index,row in attachment_qc.iterrows():
        ussm=row["USSM"]
        vpn=row["VPN name"]
        if ussm.strip()=="Milbradt, Thomas (Z000F1XC)" and vpn.strip()=="Siemens VPN":
            b=row["IP-net-base"]
            cidr=row["CIDR"]
            prefix2 = b
            cidr2 = correctAndCheckMatchedMask(cidr)
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
                # Das Folgende ist redundant, Ã¼berreichlich, ersetzt:
                #   int_prefix_top == -4117887025:
                #   if int_prefix_top < 0:
                #      int_prefix_top = int_prefix_top + (2**32)

            prefix_top = integerToDecimalDottedQuad(int_prefix_top)
            # print("netw.adrr.:{}".format(base))
            for j in range(decimalDottedQuadToInteger(base) + 1,
                           decimalDottedQuadToInteger(
                               integerToDecimalDottedQuad(int_prefix_top)) + 1):
                list_unpacked_ips.append({"ip":integerToDecimalDottedQuad(j),"base":b,"cidr":cidr,"ussm":ussm,"vpn":vpn})

    df=pandas.DataFrame(list_unpacked_ips)
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "DARWIN_DB"), pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    df.to_sql("eagle", dbConnection, if_exists='replace', index=True)
    print("Done!")

if __name__=="__main__":
    filepath_qc = "20220614-snic_ip_network_assignments.csv"
    snic_to_sql(filepath_qc)