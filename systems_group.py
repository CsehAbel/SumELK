#!/home/scripts/ticket_automatisierung/bin/python3
import datetime
import logging
import argparse
import math
import re
import shlex
import socket
import struct
import sys
import os

import pandas
from pytos.common.functions.config import Secure_Config_Parser
from pytos.common.logging.definitions import COMMON_LOGGER_NAME
from pytos.common.logging.logger import setup_loggers
from pytos.securechange.helpers import Secure_Change_Helper
from pytos.securetrack.helpers import Secure_Track_Helper
from pytos.securetrack.xml_objects.rest.rules import Host_Network_Object

import json

import secrets
import bulk_json_to_df
from sqlalchemy import create_engine


sc_helper = Secure_Change_Helper("cofw.siemens.com", (secrets.sc_u, secrets.sc_pw))
st_helper = Secure_Track_Helper("cofw-track.siemens.com", (secrets.st_u,secrets.st_pw))

log_file_path="/home/scripts/"
log_file_name="pytos_logger_sumelk.log"
config_file_path='pytos.conf'

logger = logging.getLogger(COMMON_LOGGER_NAME)
conf = Secure_Config_Parser(config_file_path=config_file_path)
setup_loggers(conf.dict("log_levels"),log_file_path,log_file_name,log_to_stdout=True)  # cli_args.debug)

def netmask_to_cidr(netmask):
    '''
    :param netmask: netmask ip addr (eg: 255.255.255.0)
    :return: equivalent cidr number to given netmask ip (eg: 24)
    '''
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))



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

def correctAndCheckMatchedMask(cidr):
    patternMask = re.compile('[^\d]*(\d+)[^\d]*$')
    resultMask = patternMask.match(cidr)
    mask = resultMask.group(1)
    mask = int(mask)
    if mask >= 8 and mask <= 32:
        return mask
    else:
        raise BaseException("Mask is less,equal to 16, mask is bigger,equal to 32")


def isMask(cidr):
    patternMask = re.compile('[^\d]*(\d+)[^\d]*$')
    resultMask = patternMask.match(cidr)
    if resultMask:
        return True
    else:
        return False

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

def ip_range_explode(ip,netmask):

        prefix2 = ip
        cidr2 = netmask_to_cidr(netmask)

        base = integerToDecimalDottedQuad(
            decimalDottedQuadToInteger(prefix2) & makeIntegerMask(
                cidr2))
        if base != prefix2:
            print("Not a network Adresse (possible ip base %s)" % base)

        int_prefix_top = (~makeIntegerMask(
            cidr2)) | decimalDottedQuadToInteger(prefix2)
        prefix_top = integerToDecimalDottedQuad(int_prefix_top)
        print("netw.adrr.:{}".format(base))
        list_unpacked_ips=[]
        for j in range(decimalDottedQuadToInteger(base) + 1,
                       decimalDottedQuadToInteger(
                           integerToDecimalDottedQuad(int_prefix_top)) + 1):
            list_unpacked_ips.append(integerToDecimalDottedQuad(j))
        return list_unpacked_ips

def append_to_list(not_g_no,input_list):
    if isinstance(not_g_no, Host_Network_Object):
        input_list.append(not_g_no.ip)
    else:
        [input_list.append(sipa) for sipa in ip_range_explode(not_g_no.ip, not_g_no.netmask)]

def get_systems_ip_list():
    device_name = "CST-P-SAG-Energy"
    device_id = st_helper.get_device_id_by_name(device_name)
    #SystemsNetworkObjects_emea = st_helper.get_network_objects_for_device(device_id)
    #group_names=[]
    # for x in SystemsNetworkObjects_emea.network_objects:
    #     if hasattr(x, 'type'):
    #         if x.type=="group":
    #             pattern_sys=re.compile(".*migrated_SNX_Systems",re.IGNORECASE)
    #             if pattern_sys.match(x.name):
    #                 group_names.append(x.name)
    group_names=['NAM_migrated_SNX_Systems','EMEA_migrated_SNX_Systems','LATAM_migrated_SNX_Systems','AAE_migrated_SNX_Systems','CHINA_migrated_SNX_Systems']
    system_ips=[]
    for gn in group_names:
        SystemsNetworkObjects = st_helper.get_network_objects_for_device(device_id, "group",{"name": gn })
        for i in SystemsNetworkObjects.network_objects:
            if(hasattr(i,"ip") and hasattr(i,"netmask")):
                range={"ip":i.ip,"cidr":netmask_to_cidr(i.netmask)}
                system_ips.append("%s/%s" %(range["ip"],range["cidr"]))
            else:
                pass
    return system_ips

def get_dest_ports():
    device_name = "CST-P-SAG-Energy"
    device_id = st_helper.get_device_id_by_name(device_name)
    rules=st_helper.get_rules_for_device(device_id)
    patternApp=re.compile("^a.*",re.IGNORECASE)
    patternWuser=re.compile("^wuser.*",re.IGNORECASE)
    list_rules=[]
    for r in rules._list_data:
        if r.name=='atos_vuln_scans':#,'ai_ngfs','a_whitelist_bulk_https','a_whitelist':
            continue
        try:
            resultApp=patternApp.match(r.name)
        except Exception:
            continue
        resultWuser=patternWuser.match(r.name)

        if resultWuser or resultApp:


            try:
                lid=[x.id for x in r.dst_networks]
                l_dest_ip = []
                for x in lid:
                    try:
                        not_g_no=st_helper.get_network_object_by_device_and_object_id(device_id, x)
                        append_to_list(not_g_no,l_dest_ip)
                    except AttributeError as aex:
                        if aex.args[0]=='\'Group_Network_Object\' object has no attribute \'ip\'':
                            #not_g_no turns out to be doch group network object
                            lid12=[bo1.id for bo1 in not_g_no.members._list_data]
                            for x12 in lid12:
                                try:
                                    not_g_no2 = st_helper.get_network_object_by_device_and_object_id(device_id, x12)
                                    append_to_list(not_g_no2,l_dest_ip)
                                except Exception as qex:
                                    if qex.args[0] == '\'Group_Network_Object\' object has no attribute \'ip\'':
                                        # not_g_no turns out to be doch group network object
                                        lid123 = [bo1.id for bo1 in not_g_no2.members._list_data]
                                        for x123 in lid123:
                                            try:
                                                not_g_no3 = st_helper.get_network_object_by_device_and_object_id(
                                                    device_id, x123)
                                                append_to_list(not_g_no3, l_dest_ip)
                                            except Exception as qex2:
                                                if qex2.args[
                                                    0] == '\'Group_Network_Object\' object has no attribute \'ip\'':
                                                    # not_g_no turns out to be doch group network object
                                                    lid1234 = [bo1.id for bo1 in not_g_no3.members._list_data]
                                                    for x1234 in lid1234:
                                                        try:
                                                            not_g_no4 = st_helper.get_network_object_by_device_and_object_id(
                                                                device_id, x1234)
                                                            append_to_list(not_g_no4, l_dest_ip)
                                                        except Exception as qex23:
                                                            raise qex23
                                                else:
                                                    raise qex2
                                    else:
                                        raise qex
                        elif aex.args[0]=='\'Range_Network_Object\' object has no attribute \'ip\'':
                            r_no=st_helper.get_network_object_by_device_and_object_id(device_id, x)
                            for ra in range(ip2int(r_no.first_ip),ip2int(r_no.last_ip)+1):
                                r_ip=int2ip(ra)
                                l_dest_ip.append(r_ip)

                        else:
                            raise aex
                    except ValueError as vex:
                        patternNotExist=re.compile("Network object with id \d+ does not exists on device id 1")
                        resultNotExist=patternNotExist.match(aex.args[0])
                        if not resultNotExist :
                            raise vex
                        else:
                            patternPrefix = re.compile(
                                '^\s*SAG_(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))\s*$')
                            resultPrefix = patternPrefix.match(x.name) #'SAG_163.242.205.140'
                            dip=resultPrefix.group(1)
                            l_dest_ip.append(dip)



                lid=[x.id for x in r.dst_services]
                #gibt Liste von Services_List zurück
                #Services_List beinhaltet services Feld
                # services Feld ist eine Liste
                l_sl_sf_l=[st_helper.get_services_by_device_and_object_ids(device_id, x) for x in lid]
                #Liste von services Feld
                l_sf_l=[sl.services for sl in l_sl_sf_l]
                l_e=[]
                for sf_l in l_sf_l:
                    for e in sf_l:
                        try:
                            l_e.append((e.max,e.min,e.protocol,e.display_name))
                        except Exception as xex2:
                            if xex2.args[0]=='\'Group_Service\' object has no attribute \'max\'':
                                lid2=[bo.id for bo in e.members._list_data]
                                l_sl_sf_l2=[st_helper.get_services_by_device_and_object_ids(device_id, x) for x in lid2]
                                l_sf_l2 = [sl.services for sl in l_sl_sf_l2]
                                for sf_l2 in l_sf_l2:
                                    for e2 in sf_l2:

                                        try:
                                            l_e.append((e2.max, e2.min, e2.protocol,e2.display_name))
                                        except Exception as ex3:
                                            if ex3.args[0] == '\'Group_Service\' object has no attribute \'max\'':
                                                lid3 = [bo.id for bo in e2.members._list_data]
                                                l_sl_sf_l3 = [
                                                    st_helper.get_services_by_device_and_object_ids(device_id, x) for x
                                                    in lid3]
                                                l_sf_l3 = [sl.services for sl in l_sl_sf_l3]
                                                for sf_l3 in l_sf_l3:
                                                    for e3 in sf_l3:

                                                        try:
                                                            l_e.append((e3.max, e3.min, e3.protocol,e3.display_name))
                                                        except Exception as ex4:
                                                            raise ex4

                            else:
                                raise xex2

                list_rules.append([[r.name,r.order,r.rule_number],l_dest_ip,l_e])
            except Exception as ex:
                raise ex
    return list_rules

#from_rule: 1, port: 415-450/tcp, ip: 10.2.
#from_rule: 1, port: 600/udp, ip: 10.2.
#from_rule: 1, port: 415-450/tcp, ip: 149.1.
#from_rule: 1, port: 415-450/tcp, ip: 149.1.
def proc_dest_port_tuples(list_rules):
    list_exploded=[]
    for i in range(len(list_rules)):
        for ip in list_rules[i][1]:
            for t in list_rules[i][2]:
                max=t[0]
                min=t[1]
                service_display_name=t[3]
                tcp_udp=""
                if t[2] == 6:
                    tcp_udp = "tcp"
                elif t[2] == 17:
                    tcp_udp = "udp"
                elif (t[2] == None) and (max==min) and (max==50):
                    tcp_udp = "esp"
                else:
                    print("")

                range_or_not= str(max) if max==min else "%d-%d" %(min,max)
                complete_port="%s/%s" %(range_or_not,tcp_udp)
                #rule.name,order,rule_number
                list_exploded.append({"st_dest_ip":ip,"st_port":complete_port,"st_serv_name":service_display_name,"rule_name":list_rules[i][0][0],"rule_order":list_rules[i][0][1],"rule_number":list_rules[i][0][2]})
    return list_exploded

def df_from_line(line):
    dict_line = json.loads(line)
    df = pandas.DataFrame(dict_line)
    return df

def dest_ports_to_file():
    list_rules = get_dest_ports()

    with open('secure_track/ports.json', 'w') as outfile:
        json.dump(list_rules, outfile)
    with open('secure_track/ports.json') as json_file:
        data = json.load(json_file)

    list_exploded = proc_dest_port_tuples(data)
    with open('secure_track/exploded.json', 'w') as outfile:
        json.dump(list_exploded, outfile)

    df = bulk_json_to_df.create_dataframe('secure_track/exploded.json', df_from_line)
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "CSV_DB"), pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    df.to_sql("st_ports", dbConnection, if_exists='replace', index=True)
    print("systems_group Done!")


def all_red_networks_systems():
    systems_ips = get_systems_ip_list()
    # not anymore system_ips
    filename = "systems.txt"
    list_old = []
    with open(filename) as infile:
        for line in infile:
            patternPrefixCIDR = re.compile('^.*\"(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/(\d+))\".*$')
            # [\s"]* anstatt \s*
            resultPrefix = patternPrefixCIDR.match(line)
            if resultPrefix:
                prefix = resultPrefix.group(1)
                list_old.append(prefix)
            else:
                raise ValueError

    # needs to be filtered out from hits ami egyszer valaha be is volt teve
    # { business_partner_001-004,
    #   (4xtransform job +
    #   1xtransform job geliefert von save_new_transform_json() new_transform.json )
    # } - { new all_red-networks systems }
    onlyInOld = set(list_old) - set(systems_ips)
    # need to be added to new transform
    #{ new all_red-networks systems } - { 4xtransform job }
    onlyInNew = set(systems_ips) - set(list_old)
    return (onlyInOld,onlyInNew)

def save_new_transform_json():

    # (onlyInOld,onlyInNew) using systems.txt to read the old list
    (onlyInOld, onlyInNew) = all_red_networks_systems()

    with open('transform.json') as json_file:
        transform = json.load(json_file)
    print("Done reading transform.json!")
    #393
    transform['bool']['filter']['terms']['source.ip'] = list(onlyInNew)

    with open('new_transform.json', 'w') as outfile:
        json.dump(transform, outfile)
    print("Done writing new_transform.json!")

    #21
    with open('onlyInOld.json', 'w') as outfile:
        for i in onlyInOld:
            json.dump(i, outfile)
            outfile.write("\n")
    print("Done writing onlyInOld.json!")

def onlyinold_to_sql():
    list_unpacked_ips = []
    with open("onlyInOld.json") as fp:
        lines = fp.readlines()
        for line in lines:
            patternPrefixCIDR = re.compile('^.*\"(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/(\d+))\".*$')
            # [\s"]* anstatt \s*
            resultPrefix = patternPrefixCIDR.match(line)
            if not resultPrefix:
                raise ValueError("onlyInOld.json not matching regex")

            prefix2 = resultPrefix.group(2)
            cidr = resultPrefix.group(3)
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
                # Das Folgende ist redundant, überreichlich, ersetzt:
                #   int_prefix_top == -4117887025:
                #   if int_prefix_top < 0:
                #      int_prefix_top = int_prefix_top + (2**32)

            prefix_top = integerToDecimalDottedQuad(int_prefix_top)
            # print("netw.adrr.:{}".format(base))
            for j in range(decimalDottedQuadToInteger(base) + 1,
                           decimalDottedQuadToInteger(
                               integerToDecimalDottedQuad(int_prefix_top)) + 1):
                list_unpacked_ips.append(integerToDecimalDottedQuad(j))

    df = pandas.DataFrame(list_unpacked_ips)
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "CSV_DB"), pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    df.to_sql("onlyinold", dbConnection, if_exists='replace', index=True)

if __name__=="__main__":
    save_new_transform_json()
    onlyinold_to_sql()
