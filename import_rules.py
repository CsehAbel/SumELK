import json
import pathlib
import re
from pathlib import Path
import pandas
import ip_utils

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

def get_dest_ports_ips(ld,members):
    ids = [x.id for x in members]
    for id in ids:
        try:
            df_obj = get_network_object_by_id(id)
            if df_obj.type.values[0]=="host":
                ld.append(df_obj.ip.values[0])
            #replace else with elif isinstance(not_g_no,?)
            elif df_obj.type.values[0]=="network":
                [ld.append(sipa) for sipa in ip_utils.ip_range_explode(df_obj.ip.values[0], df_obj.netmask.values[0])]
            elif df_obj.type.values[0]=="group":
                get_dest_ports_ips(df_obj.members)
            # else:
            #     patternPrefix = re.compile(
            #         '^\s*SAG_(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))\s*$')
            #     resultPrefix = patternPrefix.match(id.name)  # 'SAG_163.242.205.140'
            #     dip = resultPrefix.group(1)
            #     ld.append(dip)
        # except AttributeError as aex:
        #     if aex.args[0] == '\'Group_Network_Object\' object has no attribute \'ip\'':
        #         #not_g_no turns out to be doch group network object
        #         get_dest_ports_ips(device_id, ld, not_g_no.members._list_data)
        #     elif aex.args[0] == '\'Range_Network_Object\' object has no attribute \'ip\'':
        #         r_no = st_helper.get_network_object_by_device_and_object_id(device_id, id)
        #         for ra in range(ip_utils.ip2int(r_no.first_ip), ip_utils.ip2int(r_no.last_ip) + 1):
        #             r_ip = ip_utils.int2ip(ra)
        #             ld.append(r_ip)
        except ValueError as vex:
                raise vex
        except BaseException as err:
            print(f"Unexpected {err=}, {type(err)=}")
            raise

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

def get_network_object_by_id(id):
    dir_path="/home/akecse/PycharmProjectsSumELK"
    file=Path(dir_path)/"Standard_objects.json"
    with file.open() as f:
        objects=json.load(f)
    df=pandas.DataFrame(objects)
    types=df["type"].unique()
    #df_ngh keep rows where type=network, group, or host
    df_ngh = df["type"].isin(["network", "group", "host"])
    #DataFrame->Series contaning index, and a field True or False
    matches=df_ngh["uid"].isin([id])
    if 1!=matches.value_counts().loc[True]:
        error="uid not found" if matches.value_counts().loc[True]==0 else "more than one object found for uid"
        raise ValueError("%s\n\r uid: %s" %(error,id))
    #DataFrame containing single row
    df_obj=df_ngh.loc[matches]
    return df_obj


def main(path):
    #list_files checks for regex ^hit.*
    file=Path(path).absolute()
    if not file.is_file():
        raise FileNotFoundError(path)
    with file.open() as f:
        rules=json.load(f)
    print("")
    patternApp=re.compile("^a.*",re.IGNORECASE)
    patternWuser=re.compile("^wuser.*",re.IGNORECASE)
    df_rules = pandas.DataFrame(rules)
    #access-section, access-rule
    types=df_rules.type.unique()
    #there is no row which doesnt have a type
    notype = df_rules.type.isna().value_counts()
    #7 doesn't have name
    hasname = df_rules[df_rules.name.notna()]
    noname = df_rules[df_rules.name.isna()]
    for rule in rules:
        if rule.name == 'atos_vuln_scans':  # ,'ai_ngfs','a_whitelist_bulk_https','a_whitelist':
            continue
        if rule.name == "a_17042_CDC":
            print("129.73.226.0/24 should be added to return value list_rules")
        resultApp=patternApp.match(rule.name)
        resultWuser = patternWuser.match(rule.name)
        if resultWuser or resultApp:
            ld = []
            # get_dest_ports_ips(ld,r.dst_networks)
            # l_e=[]
            # get_dest_ports_ports(l_e,r.dst_services)
            # list_rules.append([[r.name, r.order, r.rule_number], ld, l_e])
            print("")

    # df=pd.concat(df_list_per_file,ignore_index=True)
    # sqlEngine = create_engine(
    #     'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "CSV_DB"), pool_recycle=3600)
    # dbConnection = sqlEngine.connect()
    # df.to_sql("ip", dbConnection, if_exists='replace', index=True)


if __name__ == '__main__':
    #path = "/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/Network-CST-P-SAG-Energy.json"
    #main(path)
    #test access section a_white
    get_network_object_by_id('40eaa8ff-8e99-4edd-a1ce-6281b9818171')