#!/home/scripts/ticket_automatisierung/bin/python3
import re
from pathlib import Path

import pandas
import json

def get_systems_ip_list(darwin_json):
    st_obj_dir_path = "./"
    st_obj_file = Path(st_obj_dir_path) / darwin_json

    if not st_obj_file.is_file():
        raise FileNotFoundError(st_obj_file.name)

    with st_obj_file.open() as sof:
        objects = json.load(sof)
    st_obj_df = pandas.DataFrame(objects)
    types = st_obj_df["type"].unique()

    of_type_group = st_obj_df[st_obj_df.type.isin(["group"])]
    group_names = ['NAM_migrated_SNX_Systems', 'EMEA_migrated_SNX_Systems', 'LATAM_migrated_SNX_Systems',
                   'AAE_migrated_SNX_Systems', 'CHINA_migrated_SNX_Systems']
    snx_systems = of_type_group[of_type_group.name.isin(group_names)]
    list_source_ranges = []
    for index, obj in snx_systems.iterrows():
        rule_name = obj["name"]
        ld = []
        get_dest_ports_ips(ld, [x["uid"] for x in obj["members"]], st_obj_df)
        [list_source_ranges.append(y) for y in ld]
    #{"subnet":,"cidr":}
    lsr=[("%s/%s" %(x["subnet"],x["cidr"])) for x in list_source_ranges]
    return lsr

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

#ld list of destination ips to complete with ips found inside group network objects
#members list of members either Host_Network_Obj or Group_Network_Obj
def get_dest_ports_ips(ld,ids,st_obj_df):
    try:
        for id in ids:
            try:
                df_obj = get_network_object_by_id(id,st_obj_df)
                if df_obj.type.values[0]=="host":
                    ld.append({"subnet":df_obj["ipv4-address"].values[0],"cidr":32})
                elif df_obj.type.values[0]=="network":
                    subnet=df_obj["subnet4"].values[0]
                    #netmask=ip_utils.cidr_to_netmask(df_obj["mask-length4"].values[0])
                    ld.append({"subnet":subnet,"cidr":df_obj["mask-length4"].values[0].__int__()})
                elif df_obj.type.values[0]=="group":
                    get_dest_ports_ips(ld,[x["uid"] for x in df_obj["members"].values[0]],st_obj_df)
                elif df_obj.type.values[0] == "address-range":
                    # for ra in range(ip_utils.ip2int(df_obj["ipv4-address-first"].values[0]), ip_utils.ip2int(df_obj["ipv4-address-last"].values[0]) + 1):
                    #     r_ip = ip_utils.int2ip(ra)
                    #     ld.append(r_ip)
                    raise ValueError("type is not netw,range")
                else:
                    raise ValueError("type is not host,netw,group,range")
            except BaseException as ex:
                    raise ex
    except BaseException as err:
        print(f"Unexpected {err=}, {type(err)=}")
        raise err

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
