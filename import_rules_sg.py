import json
import logging
import re
from pathlib import Path
import pandas
from sqlalchemy.dialects.mysql import INTEGER

import ip_utils
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Date, VARCHAR

# def get_dest_ports():
#     device_name = "CST-P-SAG-Energy"
#     rules=st_helper.get_rules_for_device(device_id)
#     patternApp=re.compile("^a.*",re.IGNORECASE)
#     patternWuser=re.compile("^wuser.*",re.IGNORECASE)
#     list_rules=[]
#     for r in rules._list_data:
#         if r.name=='atos_vuln_scans':#,'ai_ngfs','a_whitelist_bulk_https','a_whitelist':
#             continue
#         if r.name == "a_17042_CDC":
#             print("129.73.226.0/24 should be added to return value list_rules")
#         try:
#             resultApp=patternApp.match(r.name)
#         except BaseException:
#             continue
#         resultWuser=patternWuser.match(r.name)
#
#         if resultWuser or resultApp:
#             try:
#                 ld = []
#                 get_dest_ports_ips(device_id, ld, r.dst_networks)
#                 l_e=[]
#                 get_dest_ports_ports(device_id, l_e, r.dst_services)
#                 list_rules.append([[r.name, r.order, r.rule_number], ld, l_e])
#             except BaseException as ex:
#                 raise ex
#     return list_rules
import secrets

def get_dest_ports_ips(ld,ids,st_obj_df):
    try:
        for id in ids:
            try:
                df_obj = get_network_object_by_id(id,st_obj_df)
                if df_obj.type.values[0]=="host":
                    ip_value=df_obj["ipv4-address"].values[0]
                    #create a dictionary with start,end,cidr,type,start_int,end_int
                    ld.append({"start":ip_value,"end":ip_value,"cidr":32,"type":"host","start_int":ip_utils.ip2int(ip_value),"end_int":ip_utils.ip2int(ip_value)})
                elif df_obj.type.values[0]=="network":
                    subnet=df_obj["subnet4"].values[0]
                    netmask=df_obj["mask-length4"].values[0]
                    netmask=int(netmask)
                    # create a dictionary with start,end
                    base,prefix_top=ip_utils.base_cidr_to_range(subnet,netmask)
                    ld.append({"start":base,"end":prefix_top,"cidr":netmask,"type":"network","start_int":ip_utils.ip2int(base),"end_int":ip_utils.ip2int(prefix_top)})
                elif df_obj.type.values[0]=="group":
                    get_dest_ports_ips(ld,[x["uid"] for x in df_obj["members"].values[0]],st_obj_df)
                elif df_obj.type.values[0] == "address-range":
                    start=df_obj["ipv4-address-first"].values[0]
                    end=df_obj["ipv4-address-last"].values[0]
                    cidr=ip_utils.iprange_to_cidr(start,end)
                    res1=ip_utils.is_network_address(start,cidr)
                    res2=ip_utils.is_prefix_top(start,end,cidr)
                    cidr=cidr if (res1 and res2) else -1
                    ld.append({"start":start, "end":end,"cidr":cidr,"type":"range","start_int":ip_utils.ip2int(start),"end_int":ip_utils.ip2int(end)})
                else:
                    raise ValueError("type is not host,netw,group,range")
                #     patternPrefix = re.compile(
                #         '^\s*SAG_(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))\s*$')
                #     resultPrefix = patternPrefix.match(id.name)  # 'SAG_163.242.205.140'
                #     dip = resultPrefix.group(1)
                #     ld.append(dip)
            except BaseException as ex:
                    raise ex
    except BaseException as err:
        print(f"Unexpected {err=}, {type(err)=}")
        raise

def get_dest_ports_ports(l_e,lid,st_obj_df):
    # get_network_object_by_id() need repurposing to work as get_services_by_id()
    try:
        elements = [get_network_object_by_id(x,st_obj_df) for x in lid]

        for df in elements:
            for index,service in df.iterrows():
                try:
                    service_type_ = service["type"]
                    pttrn_type1 = re.compile("service-(tcp)", re.IGNORECASE)
                    res_type1=pttrn_type1.match(service_type_)
                    pttrn_type2 = re.compile("service-(udp)", re.IGNORECASE)
                    res_type2 = pttrn_type2.match(service_type_)
                    pttrn_type3 = re.compile("service-group", re.IGNORECASE)
                    res_type3 = pttrn_type3.match(service_type_)
                    pttrn_type4 = re.compile("service-other", re.IGNORECASE)
                    res_type4 = pttrn_type4.match(service_type_)
                    if res_type1 or res_type2:
                        tcp_udp=res_type1.group(1) if res_type1 else res_type2.group(1)

                        service_port_ = service["port"]

                        pttrn_port1 = re.compile("(\d+)-?(\d*)")
                        res_port1 = pttrn_port1.match(service_port_)
                        pttrn_port2 = re.compile(">(\d+)")
                        res_port2 = pttrn_port2.match(service_port_)
                        if res_port1:
                            l_e.append({"port": service_port_, "tcp_udp": tcp_udp})
                        elif res_port2:
                            min = res_port2.group(1)
                            max = "65535"
                            l_e.append({"port": "%s-%s" %(min,max), "tcp_udp": tcp_udp})

                        if not pandas.isna(service["members"]):
                            raise ValueError()
                    elif res_type3:
                        get_dest_ports_ports(l_e,[y["uid"] for y in service["members"]],st_obj_df)
                    elif res_type4:
                        l_e.append({"port": service["ip-protocol"], "tcp_udp": service["name"].lower})
                    else:
                        raise ValueError()
                except BaseException as err:
                         raise err
    except BaseException as be:
        raise be

def proc_dest_port_tuples(list_rules):
    max_services_length = 0
    list_exploded = []
    for i in range(len(list_rules)):
        for ip in list_rules[i]["destinations"]:
            #for evcery dictionary in list_rules[i]["services"] create a new dictionary with the keys "port" and "tcp_udp"
            #if "tcp_udp" is a built in function, then that built in function returns a string, which will be the value for "tcp_udp"
            #if "tcp_udp" is not a built in function, then the value for "tcp_udp" will be the value of the key "tcp_udp" in the dictionary
            list_services = []
            for t in list_rules[i]["services"]:
                port=t["port"]
                tcp_udp=t["tcp_udp"]
                if callable(tcp_udp):
                    tcp_udp=tcp_udp()
                complete_port = "%s/%s" % (port, tcp_udp)
                list_services.append(complete_port)
            # issue with having services left as is, json.dumps() didnt work for list_exploded_with_concatenated_services,
            # only worked when services was concatenated into a string
            json_services = json.dumps(list_services)
            #set max_services_length to the length json_services if it is greater than max_services_length
            max_services_length = len(json_services) if len(json_services) > max_services_length else max_services_length

            list_exploded.append(
                {"dest_ip_start": ip["start"], "dest_ip_end": ip["end"], "dest_ip_cidr": ip["cidr"],
                 "dest_ip_type": ip["type"],
                 "dest_ip_start_int": ip["start_int"], "dest_ip_end_int": ip["end_int"],
                 "json_services": json_services,  # concat_services,
                 "rule_name": list_rules[i]["name"],
                 "rule_number": "%d" % list_rules[i]["number"]})
    return list_exploded, max_services_length

def get_network_object_by_id(id,st_obj_df):
    #DataFrame->Series contaning index, and a field True or False
    matches=st_obj_df["uid"].isin([id])
    if 1!=matches.value_counts().loc[True]:
        error="uid not found" if matches.value_counts().loc[True]==0 else "more than one object found for uid"
        raise ValueError("%s\n\r uid: %s" %(error,id))
    #DataFrame containing single row
    #df_obj=df_ngh.loc[matches]
    df_obj=st_obj_df[matches]
    return df_obj


def main(path,standard_path):

    st_obj_file = Path(standard_path)
    with st_obj_file.open() as sof:
        objects = json.load(sof)
    st_obj_df = pandas.DataFrame(objects)
    types = st_obj_df["type"].unique()
    source_groups=st_obj_df[st_obj_df["type"].isin(["group"])]
    number_of_groups=st_obj_df["type"].isin(["group"]).value_counts()

    for index,group in source_groups.iterrows():
       
        #pattern for matching an ip address
        pttrn = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        #first octet cant have 0 as the first digit
        #second octet cant have 0 as the first digit
        #third octet cant have 0 as the first digit
        #fourth octet cant have 0 as the first digit
        pttrn = re.compile("^sg_.+((?!0)\d{1,3}\.(?!0)\d{1,3}\.(?!0)\d{1,3}\.(?!0)\d{1,3})$")
        #if the regex matches the name of the group, then the group is a source group
        res = pttrn.match(group["name"])
        if res:
            ld = []
            get_dest_ports_ips(ld,[x["uid"] for x in group["members"]],st_obj_df)
            # get first regex group
            name=res.group(1)
            list_rules.append({"name":name, "source ips":ld})

    # ToDo: create json from list_rules, currently using mysql instead of json
    # list_exploded is a list of dictionaries, each dictionary containing dest_ip,concat_services,rule_name,rule_number
    return list_rules

def dict_to_sql(list_unpacked_ips,max_services_length):
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "CSV_DB"),
        pool_recycle=3600)
    metadata_obj = MetaData()
    fw_policy_table = drop_and_create_fw_policy_table(metadata_obj, sqlEngine, max_services_length)

    conn = sqlEngine.connect()

    insert_to_fw_policy(conn, fw_policy_table, list_unpacked_ips)
    print("fw_policy insert done!")


def drop_and_create_fw_policy_table(metadata_obj, sql_engine, max_services_length):
    # eagle_table = Table('eagle', metadata_obj,
    #                     Column('id', Integer, primary_key=True),
    #                     Column('ip', String(15), nullable=False),
    #                     Column('base', String(15), nullable=False),
    #                     Column('cidr', Integer, nullable=False)
    #                     )
    # create similar table for proc_list_rules_for_sql()'s list_exploded_with_concatenated_services
    fw_policy_table = Table('fwpolicy', metadata_obj,
                            Column('id', Integer, primary_key=True),
                            Column('dest_ip_start', String(15), nullable=False),
                            Column('dest_ip_end', String(15), nullable=False),
                            #can be -1 if dest_ip_type is range, it needs to be signed
                            Column('dest_ip_cidr', Integer, nullable=False),
                            Column('dest_ip_type', String(15), nullable=False),
                            Column('dest_ip_start_int', INTEGER(unsigned=True), nullable=False),
                            Column('dest_ip_end_int', INTEGER(unsigned=True), nullable=False),
                            Column('json_services', VARCHAR(length=max_services_length), nullable=False),
                            #What the fuck ist this rule name? Can it be that the APP_ID's are appended to the end of the rule name?
                            #only if every rule could be correleted to an APP_ID, but this is not the case
                            #if it would be the case, then the APP_ID in the  ruleset could be used as a foreign key to find the
                            #fw policy rule, but now we are using the dest_ip instead
                            #app_id is only relevant from tsa expiration perspective
                            #if the tsa expires for a app id but there is another app id for the same dest_ip then keep the rule in the fw policy
                            #connection wont be refused for the app id that has its tsa expired
                            #'wuser_2168;2166;2176;2198;2220;2526;3622;3744;4303;4818;5154;5155;6144;4791;6069'.__len__()==80
                            Column('rule_name', String(80), nullable=False),
                            Column('rule_number', String(15), nullable=False)
                            )

    fw_policy_table.drop(sql_engine, checkfirst=True)
    fw_policy_table.create(sql_engine, checkfirst=False)
    return fw_policy_table

def insert_to_fw_policy(conn, table, list_unpacked_ips):
    slices = to_slices(1000, list_unpacked_ips)
    # for each slice of 1000 rows insert into the eagle table
    for s in slices:
        # try to insert the slice into the eagle table
        try:
            # check if the dictionaries in the slice have values where pandas.isnull() is True
            # if so, replace with None
            for d in s:
                for k, v in d.items():
                    if pandas.isnull(v):
                        d[k] = None
            conn.execute(table.insert().values(s))
        except Exception as e:
            #insert_fw_policy logger set to level=ERROR in test_eagle.py test_import_rules() so this will not print
            logging.getLogger("insert_fw_policy").log(level=logging.WARNING,msg=e)

def to_slices(divisor, systems_ips):
    length = len(systems_ips)
    quotient, rest = divmod(length, divisor)
    slices = []  # [[list[0],...list[999]],]
    lower_bound = 0
    for i in range(quotient + 1):
        upper_bound = (i + 1) * divisor
        if upper_bound < length:
            slices.append(systems_ips[slice(lower_bound, upper_bound, 1)])
        else:
            slices.append(systems_ips[slice(lower_bound, length, 1)])
        lower_bound = upper_bound
    return slices
    
if __name__=="__main__":
    #get the ruleset from the firewall
    standard_path = "Standard_objects.json"
    path = "./Network-CST-P-SAG-Energy.json"
    list_rules = main(path, standard_path)
    list_exploded, max_services_length = proc_dest_port_tuples(list_rules)