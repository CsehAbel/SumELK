import pandas as pd

if __name__=="__main__":
    list_hits=pd.read_csv('df_hits.csv')

    snic_file = "20220210-snic_ip_network_assignments.csv"
    df_snic = pd.read_csv(snic_file, sep=';', encoding="latin-1", dtype='str')

    file = "sysdb_2022-02-07.gz"
    df_sysdb = pd.read_csv(file, sep=';', encoding="utf-8", dtype='str')
    df_sysdb=df_sysdb[["ip","dns"]]

    hits_enriched=pd.merge(left=list_hits,right=df_sysdb,left_on="dest_ip",right_on="ip")
