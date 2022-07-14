import shutil
from datetime import datetime
from pathlib import Path
from tarfile import TarFile
import re

project_dir=Path("/home/akecse/PycharmProjectsSumELK")

def delete_hits(dir):
    hits_folder=Path(project_dir/dir)
    b_exists = hits_folder.exists()
    b_is_dir = hits_folder.is_dir()
    if b_exists and b_is_dir:
        for child in hits_folder.iterdir():
            unlink_file(child.resolve().__str__(),child.name,child)
            print("%s unlinked" % child.resolve().__str__())


def extract_policy_to_project_dir():
    #find index of standard_objects,network_objects
    network="Network-CST-P-SAG-Darwin.json"
    # ToDo: use Standard_objects.json for query_wp branch
    standard="Standard_objects.json"

    network_file=(project_dir/network)
    standard_file=(project_dir/standard)
    #Save location of deleted files, target of extracted files
    abs_network_string=network_file.resolve().__str__()
    abs_standard_string=standard_file.resolve().__str__()

    unlink_file(abs_network_string,network, network_file)
    unlink_file(abs_standard_string,standard,standard_file)

    #find network,standard in tar and extract it to
    #target:
    #abs_network_string, abs_standard_darwin_string
    darwin_policy_dir = Path('/mnt/z/darwin/darwin_cofw_policies/')
    pttrn=re.compile("^DARWIN_policy.*\.tar\.gz")
    newest_tar_gz = search_newest_in_folder(darwin_policy_dir, pttrn)
    extract_tarinfo(newest_tar_gz,abs_network_string, abs_standard_string, network, standard)
    print("extraction done!")

def search_newest_in_folder(dir, pttrn):
    b_exists = dir.exists()
    b_is_dir = dir.is_dir()
    stats = []
    if b_exists and b_is_dir:
        for child in dir.iterdir():
            res = pttrn.match(child.name)
            if res:
                stats.append(child)
    newest_tar_gz = max(stats, key=lambda x: x.stat().st_mtime)
    return newest_tar_gz

def extract_tarinfo(newest_tar_gz,abs_network_file, abs_standard_darwin_file, network, standard):
    tar_gz = TarFile.open(name=newest_tar_gz.resolve().__str__(), mode='r:gz')
    tar_members = tar_gz.getmembers()
    network_tarinfo = list(filter(lambda x: (x.name in [network]), tar_members))
    if network_tarinfo.__len__() != 1:
        raise ValueError("network_tarinfo file not found")
    network_tarinfo=network_tarinfo[0]

    standard_tarinfo = list(filter(lambda x: (x.name in [standard]), tar_members))
    if standard_tarinfo.__len__() != 1:
        raise ValueError("standard_tarinfo file not found")
    standard_tarinfo=standard_tarinfo[0]
    # Extract a member from the archive to the current working directory, using its full name
    # You can specify a different directory using path
    # member may be a filename or TarInfo object
    tar_gz.extract(member=network_tarinfo.name, path="", set_attrs=True, numeric_owner=False)
    exists1 = Path(abs_network_file).exists()
    if not exists1:
        raise RuntimeError("file %s wasnt extracted to %s" % (network, project_dir.name))
    tar_gz.extract(member=standard_tarinfo.name, path="", set_attrs=True, numeric_owner=False)
    exists2 = Path(abs_standard_darwin_file).exists()
    if not exists2:
        raise RuntimeError("file %s wasnt extracted to %s" % (standard, project_dir.name))


def unlink_file(check_if_exists_path, print_out_path, to_be_unlinked_file):
    try:
        to_be_unlinked_file.unlink()
        print("%s unlinked" % check_if_exists_path)
    except FileNotFoundError:
        print("%s not found" % check_if_exists_path)
    exists_still = Path(check_if_exists_path).is_file()
    if exists_still:
        raise RuntimeError("files %s to be deleted form %s still exists" % (print_out_path, project_dir.name))

def rename_darwin_transform_json():
    source=Path("darwin_transform.json")
    if not source.exists():
        print(source.name + " not in dir, nothing to be rename\n")
    else:
        dtm=datetime.datetime.now()
        d_m=dtm.strftime("%d_%m")
        target_string=("%s_darwin_transform.json" %d_m)
        target = Path(target_string)
        if not target.exists():
            source.rename(target_string)
            print(source.name+"\n renamed to \n"+target.name)

def one_file_found_in_folder(filepath_list, project_dir, pttrn_snic):
    for x in project_dir.iterdir():
        if pttrn_snic.match(x.name):
            filepath_list.append(x.resolve().__str__())
    if filepath_list.__len__() != 1:
        raise ValueError(project_dir.name+": more than one file matching "+pttrn_snic.pattern)

def remove_files_in_project_dir(pttrn_ruleset):
    for x in project_dir.iterdir():
        if pttrn_ruleset.match(x.name):
            unlink_file(x.resolve().__str__(),x.name,x)
            print("%s unlinked" %x.resolve().__str__())

if __name__=="__main__":
    remove_files_in_project_dir(
        pttrn_ruleset=re.compile("darwin_ruleset_unpacked\d{2}[A-Za-z]{3}\d{4}\.xlsx$"))
    extract_policy_to_project_dir()
    # remove snic.csv
    pttrn_snic = re.compile("\d{4}\d{2}\d{2}-snic_ip_network_assignments\.csv$")
    remove_files_in_project_dir(pttrn_ruleset=pttrn_snic)
    # copy new snic.csv
    newest_snic = search_newest_in_folder(dir=Path('/mnt/y/'),
                                          pttrn=pttrn_snic)
    shutil.copy(src=newest_snic,
                dst=Path("./") / newest_snic.name)
    # delete hits
    delete_hits(dir="darwin_hits")
    # renames new_transform.json
    rename_darwin_transform_json()