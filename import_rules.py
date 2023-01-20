import json
import logging
import re
from pathlib import Path
import pandas
from sqlalchemy.dialects.mysql import INTEGER

import ip_utils
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Date, VARCHAR

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
                elif df_obj.type.values[0] == "CpmiAnyObject":
                    pass
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
                    pttrn_type5 = re.compile("CpmiAnyObject", re.IGNORECASE)
                    res_type5 = pttrn_type5.match(service_type_)
                    pttrn_type6 = re.compile("service-icmp", re.IGNORECASE)
                    res_type6 = pttrn_type6.match(service_type_)
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
                    elif res_type5:
                        pass
                    elif res_type6:
                        l_e.append({"port": service["name"]+"icmp", "tcp_udp": service["name"]+"icmp"})
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
            max_services_length = len("%s" %list_services) if len("%s" %list_services) > max_services_length else max_services_length

            list_exploded.append(
                {"dest_ip_start": ip["start"], "dest_ip_end": ip["end"], "dest_ip_cidr": ip["cidr"],
                 "dest_ip_type": ip["type"],
                 "dest_ip_start_int": ip["start_int"], "dest_ip_end_int": ip["end_int"],
                 "json_services": "%s" %list_services,  # concat_services,
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
    #list_files checks for regex ^hit.*
    file=Path(path).absolute()
    if not file.is_file():
        raise FileNotFoundError(path)
    with file.open() as f:
        rules=json.load(f)

    patternApp=re.compile("^a_.*",re.IGNORECASE)
    patternApp2=re.compile("^app_.*",re.IGNORECASE)
    patternWuser=re.compile("^wuser.*",re.IGNORECASE)
    df_rules = pandas.DataFrame(rules)
    #access-section, access-rule
    types=df_rules.type.unique()
    df_rules = df_rules[df_rules["type"].isin(["access-rule"])]
    #there is no row which doesnt have a type
    notype = df_rules.type.isna().value_counts()
    #7 doesn't have name
    hasname = df_rules[df_rules.name.notna()]
    noname = df_rules[df_rules.name.isna()]
    df_rules=df_rules[df_rules.name.notna()]
    list_rules=[]

    st_obj_file = Path(standard_path)
    with st_obj_file.open() as sof:
        objects = json.load(sof)
    st_obj_df = pandas.DataFrame(objects)
    types = st_obj_df["type"].unique()
    # df_ngh keep rows where type=network, group, or host
    # usage inside get_dest_ports_ips()
    # df_ngh = st_obj_df[st_obj_df["type"].isin(["network", "group", "host","address-range"])]
    # usage inside get_dest_ports_ports()
    # df_ngh = st_obj_df[st_obj_df["type"].isin(["services"])]


    for index,rule in df_rules.iterrows():
        rule_name = rule["name"]
        if rule_name.find('atos_vuln_scans')!=-1:  # ,'ai_ngfs','a_whitelist_bulk_https','a_whitelist':
            continue
        resultApp=patternApp.match(rule_name)
        resultApp2=patternApp2.match(rule_name)
        resultWuser = patternWuser.match(rule_name)
        if resultWuser or resultApp or resultApp2:
            #fills ld with a list of dictionaries, each dictionary containnig start,end,cidr,type,start_int,end_int
            ld = []
            get_dest_ports_ips(ld,rule["destination"],st_obj_df)
            #fills l_e with a list of dictionaries, each dictionary containnig port,tcp_udp
            l_e=[]
            get_dest_ports_ports(l_e,rule["service"],st_obj_df)
            # list_rules.append([[r.name, r.order, r.rule_number], ld, l_e])
            sources=rule["source"]
            list_rules.append({"name":rule_name, "number":rule["rule-number"], "sources":sources, "destinations":ld, "services":l_e})

    # ToDo: create json from list_rules, currently using mysql instead of json
    # list_exploded is a list of dictionaries, each dictionary containing dest_ip,concat_services,rule_name,rule_number
    return list_rules

def dict_to_sql(list_unpacked_ips,max_services_length, db_name):
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", db_name),
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