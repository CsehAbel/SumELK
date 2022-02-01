#!/home/scripts/ticket_automatisierung/bin/python3
import datetime
import logging
import argparse
import math
import re
import shlex
import sys
import os

import pandas
from pytos.common.functions.config import Secure_Config_Parser
from pytos.common.logging.definitions import COMMON_LOGGER_NAME
from pytos.common.logging.logger import setup_loggers
from pytos.securechange.helpers import Secure_Change_Helper
from pytos.securechange.xml_objects.rest import Group_Change_Member_Object
from pytos.securetrack.helpers import Secure_Track_Helper
from pytos.common.definitions.xml_tags import Attributes
from pytos.securechange.xml_objects.rest import Group_Change_Member_Object,Group_Change_Node,Step_Field_Multi_Group_Change
from pytos.common.base_types import XML_List

from elasticsearch import Elasticsearch
import json
from ssl import create_default_context
from elasticsearch import RequestsHttpConnection

import secrets


sc_helper = Secure_Change_Helper("cofw.siemens.com", (secrets.sc_u, secrets.sc_pw))
st_helper = Secure_Track_Helper("cofw-track.siemens.com", (secrets.st_u,secrets.st_pw))

log_file_path="/home/scripts/"
log_file_name="pytos_logger_sumelk.log"
config_file_path='pytos.conf'

logger = logging.getLogger(COMMON_LOGGER_NAME)
conf = Secure_Config_Parser(config_file_path=config_file_path)
setup_loggers(conf.dict("log_levels"),log_file_path,log_file_name,log_to_stdout=True)  # cli_args.debug)

def find_migrated_SNX_groups(OfficeOrSystems, OfficeNetworkObjects, SystemsNetworkObjects, domainid, groupName):
    if OfficeOrSystems == "Office":
        groupOfficeSearch = st_helper.get_network_objects_group_by_member_object_id(
            OfficeNetworkObjects.network_objects[0].id, domainid)

        for group in groupOfficeSearch.network_objects:
            if group.__class__.__name__ == "Group_Network_Object" and group.name == groupName:
                groupOfficeSearchResult = group
                return groupOfficeSearchResult
        raise ValueError("no returned search result")
    elif OfficeOrSystems == "Systems":
        groupSystemsSearch = st_helper.get_network_objects_group_by_member_object_id(
            SystemsNetworkObjects.network_objects[0].id, domainid)

        for group in groupSystemsSearch.network_objects:
            if group.__class__.__name__ == "Group_Network_Object" and group.name == groupName:
                groupSystemsSearchResult = group
                return groupSystemsSearchResult
        raise ValueError("no returned search result")
    else:
        raise ValueError(
            "parameter to choose the group based on which REGION_migrated_SNX_Office/Systems will be instantiated doesnt match neither 'Office' nor 'Systems' ")

def netmask_to_cidr(netmask):
    '''
    :param netmask: netmask ip addr (eg: 255.255.255.0)
    :return: equivalent cidr number to given netmask ip (eg: 24)
    '''
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def main():
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

    print("lel")


if __name__=="__main__":
    main()

