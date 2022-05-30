import json
import pathlib
import re
from pathlib import Path
import pandas
import ip_utils
from sqlalchemy import create_engine

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
                    ld.append(df_obj["ipv4-address"].values[0])
                #replace else with elif isinstance(not_g_no,?)
                elif df_obj.type.values[0]=="network":
                    subnet=df_obj["subnet4"].values[0]
                    netmask=ip_utils.cidr_to_netmask(df_obj["mask-length4"].values[0])
                    [ld.append(sipa) for sipa in ip_utils.ip_range_explode(subnet, netmask)]
                elif df_obj.type.values[0]=="group":
                    get_dest_ports_ips(ld,[x["uid"] for x in df_obj["members"].values[0]],st_obj_df)
                elif df_obj.type.values[0] == "address-range":
                    for ra in range(ip_utils.ip2int(df_obj["ipv4-address-first"].values[0]), ip_utils.ip2int(df_obj["ipv4-address-last"].values[0]) + 1):
                        r_ip = ip_utils.int2ip(ra)
                        ld.append(r_ip)
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

#from_rule: 1, port: 415-450/tcp, ip: 10.2.
#from_rule: 1, port: 600/udp, ip: 10.2.
#from_rule: 1, port: 415-450/tcp, ip: 149.1.
#from_rule: 1, port: 415-450/tcp, ip: 149.1.
def proc_dest_port_tuples(list_rules):
    list_exploded=[]
    for i in range(len(list_rules)):
        for ip in list_rules[i]["destinations"]:
            for t in list_rules[i]["services"]:
                port=t["port"]
                tcp_udp=t["tcp_udp"]
                complete_port="%s/%s" %(port,tcp_udp)
                list_exploded.append({"st_dest_ip":ip,"st_port":complete_port,"rule_name":list_rules[i]["name"],"rule_number":"%d" %list_rules[i]["number"]})
    return list_exploded

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


def main(path):
    #list_files checks for regex ^hit.*
    file=Path(path).absolute()
    if not file.is_file():
        raise FileNotFoundError(path)
    with file.open() as f:
        rules=json.load(f)

    patternApp=re.compile("^a.*",re.IGNORECASE)
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

    st_obj_dir_path = "./"
    st_obj_file = Path(st_obj_dir_path) / "Standard_objects.json"
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
        if rule_name == 'atos_vuln_scans':  # ,'ai_ngfs','a_whitelist_bulk_https','a_whitelist':
            continue
        if rule_name == "a_17042_CDC":
            print("129.73.226.0/24 should be added to return value list_rules")
        resultApp=patternApp.match(rule_name)
        resultWuser = patternWuser.match(rule_name)
        if resultWuser or resultApp:
            ld = []
            get_dest_ports_ips(ld,rule["destination"],st_obj_df)
            l_e=[]
            get_dest_ports_ports(l_e,rule["service"],st_obj_df)
            # list_rules.append([[r.name, r.order, r.rule_number], ld, l_e])
            sources=rule["source"]
            list_rules.append({"name":rule_name, "number":rule["rule-number"], "sources":sources, "destinations":ld, "services":l_e})


    list_exploded=proc_dest_port_tuples(list_rules)
    print("")
    dfx=pandas.DataFrame(list_exploded)
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "CSV_DB"), pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    dfx.to_sql("st_ports", dbConnection, if_exists='replace', index=True)
    print("import_rules.py Done!")


if __name__ == '__main__':
    path = "./Network-CST-P-SAG-Energy.json"
    main(path)
    #test access section a_white
    #get_network_object_by_id('40eaa8ff-8e99-4edd-a1ce-6281b9818171')