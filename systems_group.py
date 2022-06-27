#!/home/scripts/ticket_automatisierung/bin/python3
import logging
import re

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
import ip_utils
from pathlib import Path


sc_helper = Secure_Change_Helper("cofw.siemens.com", (secrets.sc_u, secrets.sc_pw))
st_helper = Secure_Track_Helper("cofw-track.siemens.com", (secrets.st_u,secrets.st_pw))

log_file_path="/home/scripts/"
log_file_name="pytos_logger_sumelk.log"
config_file_path='pytos.conf'

logger = logging.getLogger(COMMON_LOGGER_NAME)
conf = Secure_Config_Parser(config_file_path=config_file_path)
setup_loggers(conf.dict("log_levels"),log_file_path,log_file_name,log_to_stdout=True)  # cli_args.debug)

def get_white_rules(df_rules):
    #DataFrame->Series contaning index, and a field True or False
    a = df_rules[df_rules["type"].isin(["access-section"])]
    b = a["name"].isin(["white rules"])
    #Anzahl der 'True' values
    c = b.value_counts().loc[True]
    if 1 != c:
        error = "'white_rules' not found" if c == 0 else "more than one object found for uid"
        raise ValueError("%s\n\r uid: %s" % (error, id))
    white_rules = a[b].iloc[0]
    return white_rules

def get_systems_ip_list(darwin_json):
    st_obj_dir_path = "./"
    st_obj_file = Path(st_obj_dir_path) / darwin_json

    if not st_obj_file.is_file():
        raise FileNotFoundError(st_obj_file.name)

    # df_rules = pandas.DataFrame(rules)
    # #access-section, access-rule
    # types = df_rules.type.unique()
    #
    # section=get_white_rules(df_rules)
    # _from=int(section["from"])
    # _to=int(section["to"])
    # df_rules = df_rules[df_rules["type"].isin(["access-rule"])]
    # df_rules = df_rules[df_rules["rule-number"].isin(range(_from, _to+1))]
    #
    # #there is no row which doesnt have a type
    # notype = df_rules.type.isna().value_counts()
    # #7 doesn't have name
    # noname = df_rules.name.notna().value_counts()
    # df_rules = df_rules[df_rules.name.notna()]
    with st_obj_file.open() as sof:
        objects = json.load(sof)
    st_obj_df = pandas.DataFrame(objects)
    types = st_obj_df["type"].unique()

    patternApp = re.compile("^a.*", re.IGNORECASE)
    patternWuser = re.compile("^wuser.*", re.IGNORECASE)
    list_rules = []
    # for index,rule in df_rules.iterrows():
    #     rule_name = rule["name"]
    #     resultApp=patternApp.match(rule_name)
    #     resultWuser = patternWuser.match(rule_name)
    #     if resultWuser or resultApp:
    #         ld = []
    #         get_dest_ports_ips(ld,rule["destination"],st_obj_df)
    #         l_e=[]
    #         get_dest_ports_ports(l_e,rule["service"],st_obj_df)
    #         # list_rules.append([[r.name, r.order, r.rule_number], ld, l_e])
    #         sources=rule["source"]
    #         list_rules.append({"name":rule_name, "number":rule["rule-number"], "sources":sources, "destinations":ld, "services":l_e})


    list_exploded=proc_dest_port_tuples(list_rules)
    print("")
    dfx=pandas.DataFrame(list_exploded)

#def get_systems_ip_list():
#     device_name = "CST-P-SAG-Energy"
#     device_id = st_helper.get_device_id_by_name(device_name)
#     #SystemsNetworkObjects_emea = st_helper.get_network_objects_for_device(device_id)
#     #group_names=[]
#     # for x in SystemsNetworkObjects_emea.network_objects:
#     #     if hasattr(x, 'type'):
#     #         if x.type=="group":
#     #             pattern_sys=re.compile(".*migrated_SNX_Systems",re.IGNORECASE)
#     #             if pattern_sys.match(x.name):
#     #                 group_names.append(x.name)
#     group_names=['NAM_migrated_SNX_Systems','EMEA_migrated_SNX_Systems','LATAM_migrated_SNX_Systems','AAE_migrated_SNX_Systems','CHINA_migrated_SNX_Systems']
#     system_ips=[]
#     for gn in group_names:
#         SystemsNetworkObjects = st_helper.get_network_objects_for_device(device_id, "group",{"name": gn })
#         for i in SystemsNetworkObjects.network_objects:
#             if(hasattr(i,"ip") and hasattr(i,"netmask")):
#                 range={"ip":i.ip,"cidr":ip_utils.netmask_to_cidr(i.netmask)}
#                 system_ips.append("%s/%s" %(range["ip"],range["cidr"]))
#             else:
#                 pass
#     return system_ips

#ld list of destination ips to complete with ips found inside group network objects
#members list of members either Host_Network_Obj or Group_Network_Obj
def get_dest_ports_ips(device_id,ld,members):
    ids = [x.id for x in members]
    for id in ids:
        try:
            not_g_no = st_helper.get_network_object_by_device_and_object_id(device_id, id)
            if isinstance(not_g_no, Host_Network_Object):
                ld.append(not_g_no.ip)
            #replace else with elif isinstance(not_g_no,?)
            else:
                [ld.append(sipa) for sipa in ip_utils.ip_range_explode(not_g_no.ip, not_g_no.netmask)]
        except AttributeError as aex:
            if aex.args[0] == '\'Group_Network_Object\' object has no attribute \'ip\'':
                #not_g_no turns out to be doch group network object
                get_dest_ports_ips(device_id, ld, not_g_no.members._list_data)
            elif aex.args[0] == '\'Range_Network_Object\' object has no attribute \'ip\'':
                r_no = st_helper.get_network_object_by_device_and_object_id(device_id, id)
                for ra in range(ip_utils.ip2int(r_no.first_ip), ip_utils.ip2int(r_no.last_ip) + 1):
                    r_ip = ip_utils.int2ip(ra)
                    ld.append(r_ip)

            else:
                raise aex
        except ValueError as vex:
            patternNotExist = re.compile("Network object with id \d+ does not exists on device id 1")
            resultNotExist = patternNotExist.match(aex.args[0])
            if not resultNotExist:
                raise vex
            else:
                patternPrefix = re.compile(
                    '^\s*SAG_(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))\s*$')
                resultPrefix = patternPrefix.match(id.name)  # 'SAG_163.242.205.140'
                dip = resultPrefix.group(1)
                ld.append(dip)
        except BaseException as err:
            print(f"Unexpected {err=}, {type(err)=}")
            raise

def get_dest_ports_ports(device_id,l_e,members):
    lid = [x.id for x in members]
    # gibt Liste von Services_List zurück
    # Services_List beinhaltet services Feld
    # services Feld ist eine Liste
    l_sl_sf_l = [st_helper.get_services_by_device_and_object_ids(device_id, x) for x in lid]
    # Liste von services Feld
    l_sf_l = [sl.services for sl in l_sl_sf_l]

    for sf_l in l_sf_l:
        for e in sf_l:
            try:
                l_e.append((e.max, e.min, e.protocol, e.display_name))
            except BaseException as err:
                if err.args[0] == '\'Group_Service\' object has no attribute \'max\'':
                    get_dest_ports_ports(device_id, l_e, e.members._list_data)
                else:
                    raise err

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
        if r.name == "a_17042_CDC":
            print("129.73.226.0/24 should be added to return value list_rules")
        try:
            resultApp=patternApp.match(r.name)
        except BaseException:
            continue
        resultWuser=patternWuser.match(r.name)

        if resultWuser or resultApp:
            try:
                ld = []
                get_dest_ports_ips(device_id, ld, r.dst_networks)
                l_e=[]
                get_dest_ports_ports(device_id, l_e, r.dst_services)
                list_rules.append([[r.name, r.order, r.rule_number], ld, l_e])
            except BaseException as ex:
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

def main():
    darwin_json = "Standard_objects_darwin.json"
    get_systems_ip_list(darwin_json)

if __name__=="__main__":
    main()
    print("systems_group.py done!")
