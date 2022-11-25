import datetime
import re
import shutil
from pathlib import Path
from tarfile import TarFile
import ssh_download

import ssh_download

project_dir=Path("/home/akecse/PycharmProjectsSumELK")

def delete_hits(dir):
    hits_folder=Path(project_dir/dir)
    b_exists = hits_folder.exists()
    b_is_dir = hits_folder.is_dir()
    #keeping gitkeep in hits folder for git to be able to persist it across 'branch_switching'
    pttrn = re.compile("^.*hit.*\.json$")
    if b_exists and b_is_dir:
        for child in hits_folder.iterdir():
            if pttrn.match(child.name):
                unlink_file(child)
                print("%s unlinked" % child.resolve().__str__())

def extract_policy_to_project_dir(pttrn,network_file,standard_file,fromHere,toHere):
    network_file=(project_dir/network_file)
    standard_file=(project_dir/standard_file)

    unlink_file(network_file)
    unlink_file(standard_file)

    newest_tar_gz = ssh_download.download_file(pttrn,fromHere=fromHere,toHere=toHere)

    extract_to = Path("/mnt/c/Users/z004a6nh/PycharmProjects/SumELK/")
    extract_tarinfo(Path(newest_tar_gz),network_file,standard_file,extract_to)
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

def extract_tarinfo(newest_tar_gz,network_file,standard_file,extract_to):
    abs_network_string = network_file.resolve().__str__()
    abs_standard_string = standard_file.resolve().__str__()
    tar_gz = TarFile.open(name=newest_tar_gz.resolve().__str__(), mode='r:gz')
    tar_members = tar_gz.getmembers()

    network_tarinfo = list(filter(lambda x: (x.name in [network_file.name]), tar_members))
    if network_tarinfo.__len__() != 1:
        raise ValueError("network_tarinfo file not found")
    network_tarinfo = network_tarinfo[0]
    # Extract a member from the archive to the current working directory, using its full name
    # You can specify a different directory using path
    # member may be a filename or TarInfo object
    tar_gz.extract(member=network_tarinfo.name, path=extract_to, set_attrs=True, numeric_owner=False)
    exists1 = network_file.exists()
    if not exists1:
        raise RuntimeError("file %s wasnt extracted to %s" % (network_file.name, project_dir.name))
    else:
        print("%s extracted to %s" % (network_file.name, project_dir.name))
    standard_tarinfo = list(filter(lambda x: (x.name in [standard_file.name]), tar_members))
    if standard_tarinfo.__len__() != 1:
        raise ValueError("standard_tarinfo file not found")
    standard_tarinfo = standard_tarinfo[0]
    # Extract a member from the archive to the current working directory, using its full name
    # You can specify a different directory using path
    # member may be a filename or TarInfo object
    tar_gz.extract(member=standard_tarinfo.name, path=extract_to, set_attrs=True, numeric_owner=False)
    exists2 = standard_file.exists()
    if not exists2:
        raise RuntimeError("file %s wasnt extracted to %s" % (standard_file.name, project_dir.name))
    else:
        print("%s extracted to %s" % (standard_file.name, project_dir.name))


def unlink_file(to_be_unlinked_file):
    try:
        to_be_unlinked_file.unlink()
        print("%s unlinked" % to_be_unlinked_file.name)
    except FileNotFoundError:
        print("%s not found" % to_be_unlinked_file.name)
    exists_still = to_be_unlinked_file.is_file()
    if exists_still:
        raise RuntimeError("files %s to be deleted still exists" % to_be_unlinked_file.name)

def rename_darwin_transform_json():
    source=Path("fokus_transform.json")
    if not source.exists():
        print(source.name + " not in dir, nothing to be rename\n")
    else:
        dtm=datetime.datetime.now()
        d_m=dtm.strftime("%d_%m")
        target_string=("%s_fokus_transform.json" %d_m)
        target = Path("./transform_history") / target_string
        if not target.exists():
            shutil.copy(src=source,
                        dst=target)
            unlink_file(source)
            print(source.name+"\n renamed to \n"+target.name)

def one_file_found_in_folder(filepath_list, project_dir, pttrn_snic):
    for x in project_dir.iterdir():
        if pttrn_snic.match(x.name):
            filepath_list.append(x.resolve().__str__())
    if filepath_list.__len__() != 1:
        raise ValueError(project_dir.name+": more than one file matching "+pttrn_snic.pattern)

def remove_files_in_project_dir(pttrn_ruleset):
    remove_files_in_dir(pttrn_ruleset,project_dir)

def remove_files_in_dir(pttrn,dir):
    for x in dir.iterdir():
        if pttrn.match(x.name):
            unlink_file(x)
            print("%s unlinked" %x.resolve().__str__())

