import functools
import re

import paramiko
from pip._vendor.pyparsing import pyparsing_test

import secrets


class AllowAnythingPolicy(paramiko.MissingHostKeyPolicy):
    def missing_host_key(self, client, hostname, key):
        return

def get_newest(pttrn, policies,sftp):
    stats = []
    sftp.chdir(policies)
    for filename in sorted(sftp.listdir()):
        res = pttrn.match(filename)
        if res:
            stats.append(filename)
    newest_tar_gz = max(stats, key=lambda x: sftp.stat(x).st_mtime)
    return newest_tar_gz


def search_newest_in_folder(pttrn, policies,localdir):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(AllowAnythingPolicy())
    hostname = 'sn1fwj00.ad001.siemens.net'
    client.connect(hostname, username=secrets.gid, password=secrets.sc_pw)
    sftp = client.open_sftp()
    newest_tar_gz = get_newest(pttrn=pttrn, policies=policies, sftp=sftp)
    localpath=localdir + newest_tar_gz
    sftp.get(remotepath=newest_tar_gz,localpath=localpath,callback=lambda a,b: print(localpath + " downloaded") if a==b else None)
    client.close()
    return localpath

if __name__=="__main__":
    pttrn_snic = re.compile("\d{4}\d{2}\d{2}-snic_ip_network_assignments\.csv$")
    policies = "/D:/snic/"
    localdir="/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/policy/"
    search_newest_in_folder(pttrn=pttrn_snic,policies=policies,localdir=localdir)