import datetime
import re
import shutil
from pathlib import Path
from tarfile import TarFile
import ssh_download

import ssh_download



def delete_hits(dir):
    hits_folder=dir
    b_exists = hits_folder.exists()
    b_is_dir = hits_folder.is_dir()
    #keeping gitkeep in hits folder for git to be able to persist it across 'branch_switching'
    pttrn = re.compile("^.*hit.*\.json$")
    if b_exists and b_is_dir:
        for child in hits_folder.iterdir():
            if pttrn.match(child.name):
                unlink_file(child)
                print("%s unlinked" % child.resolve().__str__())

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
    tar_gz = TarFile.open(name=newest_tar_gz.resolve().__str__(), mode='r:gz')
    tar_members = tar_gz.getmembers()

    network_tarinfo = list(filter(lambda x: (x.name in [network_file]), tar_members))
    if network_tarinfo.__len__() != 1:
        raise ValueError("network_tarinfo file not found")
    network_tarinfo = network_tarinfo[0]
    # Extract a member from the archive to the current working directory, using its full name
    # You can specify a different directory using path
    # member may be a filename or TarInfo object
    tar_gz.extract(member=network_tarinfo.name, path=extract_to, set_attrs=True, numeric_owner=False)
    e_network_file = Path(extract_to) / network_file
    exists1 = e_network_file.exists()
    if not exists1:
        raise RuntimeError("file %s wasnt extracted" % (e_network_file.name))
    else:
        print("%s extracted" % (e_network_file.name))
    standard_tarinfo = list(filter(lambda x: (x.name in [standard_file]), tar_members))
    if standard_tarinfo.__len__() != 1:
        raise ValueError("standard_tarinfo file not found")
    standard_tarinfo = standard_tarinfo[0]
    # Extract a member from the archive to the current working directory, using its full name
    # You can specify a different directory using path
    # member may be a filename or TarInfo object
    tar_gz.extract(member=standard_tarinfo.name, path=extract_to, set_attrs=True, numeric_owner=False)
    e_standard_file = Path(extract_to) / standard_file
    exists2 = e_standard_file.exists()
    if not exists2:
        raise RuntimeError("file %s wasnt extracted" % (e_standard_file.name))
    else:
        print("%s extracted" % (e_standard_file.name))


def unlink_file(to_be_unlinked_file):
    try:
        to_be_unlinked_file.unlink()
        print("%s unlinked" % to_be_unlinked_file.name)
    except FileNotFoundError:
        print("%s not found" % to_be_unlinked_file.name)
    exists_still = to_be_unlinked_file.is_file()
    if exists_still:
        raise RuntimeError("files %s to be deleted still exists" % to_be_unlinked_file.name)

def rename_darwin_transform_json(source,target_string):
    if not source.exists():
        print(source.name + " not in dir, nothing to be rename\n")
    else:
        dtm=datetime.datetime.now()
        d_m=dtm.strftime("%d_%m")
        target_string=(target_string %d_m)
        target=Path(target_string)
        if not target.exists():
            shutil.copy(src=source,
                        dst=target)
            unlink_file(source)
            print(source.name+"\n renamed to \n"+target.name)

def one_file_found_in_folder(filepath_list, dir, pttrn_snic):
    for x in dir.iterdir():
        if pttrn_snic.match(x.name):
            filepath_list.append(x.resolve().__str__())
    if filepath_list.__len__() != 1:
        raise ValueError(dir.name+": more than one file matching "+pttrn_snic.pattern)

def remove_files_in_dir(pttrn,dir):
    for x in dir.iterdir():
        if pttrn.match(x.name):
            unlink_file(x)
            print("%s unlinked" %x.resolve().__str__())
