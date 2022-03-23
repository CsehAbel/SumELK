import resolveIpToName
import systems_group
import qc_to_sql
from sqlalchemy import create_engine
import secrets
import main as hits
import bulk_json_to_df

def main():

    #downloads SecureTrack
    # where rule_name like a.* and like wuser.*  and not like atos_vuln_scan
    # to CSV_DB -> st_ports
    systems_group.dest_ports_to_file()
    #first run SGRE to unpack se_ruleset
    filepath_qc = "se_ruleset_unpacked22Mar2022.xlsx"
    qc_to_sql.main(filepath_qc)

    #download hits to hits/...json
    hits.main()
    # /mnt/c/ProgramData/MySQL/MySQL Server 8.0/Uploads


    #(onlyInOld,onlyInNew)
    (onlyInOld,onlyInNex)=systems_group.all_red_networks_systems()
    onlyInOld
    #resolving ip to fqdn for white_apps
    #each time the ip-fqdn pair will be appended to CSV_DB->src_dns
    # sqlEngine = create_engine(
    #     'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "CSV_DB"), pool_recycle=3600)
    # dbConnection = sqlEngine.connect()
    # resolveIpToName.resolve_white_apps(sqlEngine, dbConnection)

if __name__=="__main__":
    main()