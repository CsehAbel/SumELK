import json

import resolveIpToName
import systems_group
import qc_to_sql
from sqlalchemy import create_engine
import secrets
import main as hits
import bulk_json_to_df

def save_new_transform_json():

    # (onlyInOld,onlyInNew) using systems.txt to read the old list
    (onlyInOld, onlyInNew) = systems_group.all_red_networks_systems()

    with open('transform.json') as json_file:
        transform = json.load(json_file)
    transform['bool']['filter']['terms']['source.ip'] = list(onlyInNew)

    with open('new_transform.json', 'w') as outfile:
        json.dump(transform, outfile)

    with open('onlyInOld.json', 'w') as outfile:
        for i in onlyInOld:
            json.dump(i, outfile)
            outfile.write("\n")

    print("")

def main():
    # downloads SecureTrack
    # where rule_name like a.* and like wuser.*  and not like atos_vuln_scan
    # to CSV_DB -> st_ports
    # systems_group.dest_ports_to_file()
    # first run SGRE to unpack se_ruleset
    # filepath_qc = "se_ruleset_unpacked22Mar2022.xlsx"
    # qc_to_sql.main(filepath_qc)

    # download hits to hits/...json
    # hits.main()
    # /mnt/c/ProgramData/MySQL/MySQL Server 8.0/Uploads

    save_new_transform_json()

    # resolving ip to fqdn for white_apps
    # each time the ip-fqdn pair will be appended to CSV_DB->src_dns
    # sqlEngine = create_engine(
    #     'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", "CSV_DB"), pool_recycle=3600)
    # dbConnection = sqlEngine.connect()
    # resolveIpToName.resolve_white_apps(sqlEngine, dbConnection)


if __name__ == "__main__":
    main()
