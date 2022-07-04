from pathlib import Path
from tarfile import TarFile
import re

project_dir=Path("/home/akecse/PycharmProjectsSumELK")

def extract_policy_to_project_dir():
    darwin_policy_dir=Path('/mnt/z/darwin/darwin_cofw_policies/')
    b_exists=darwin_policy_dir.exists()
    b_is_dir=darwin_policy_dir.is_dir()

    pttrn=re.compile("^DARWIN_policy.*\.tar\.gz")
    stats=[]
    if b_exists and b_is_dir:
        for child in darwin_policy_dir.iterdir():
            res=pttrn.match(child.name)
            if res:
                stats.append(child)
    newest_tar_gz=max(stats,key= lambda x:x.st_mtime())
    tar_gz=TarFile.open(name=newest_tar_gz.name,mode='r:gz')
    tar_members=tar_gz.getmembers()
    #find index of standard_objects,network_objects
    network="Network-CST-P-SAG-Darwin.json"
    standard="Standard_objects_darwin.json"

    two=list(filter(lambda x: (x.name in [network,standard] ), tar_members))
    if two.__len__()!=2:
        raise ValueError("two file not found")

    network_file=(project_dir/network)
    standard_file=(project_dir/standard)
    abs_network_file=network_file.absolute().name
    abs_standard_file=standard_file.absolute().name

    try:
        network_file.unlink()
    except FileNotFoundError:
        print("%s not found" %network)

    try:
        standard_file.unlink()
    except FileNotFoundError:
        print("%s not found" %standard)
    exists_still=Path(abs_standard_file).exists() or Path(abs_network_file).exists()
    if exists_still:
        raise RuntimeError("files %s %s to be deleted form %s still exists" %(network,standard,project_dir.name))

    #Extract a member from the archive to the current working directory, using its full name
    #You can specify a different directory using path
    tar_gz.extract(two[0], path=project_dir/network, set_attrs=True, numeric_owner=False)
    tar_gz.extract(two[1], path=project_dir/standard, set_attrs=True, numeric_owner=False)

#find /mnt/z/darwin/darwin_cofw_policies/ -maxdepth 1 -type f -printf "%T@ %Tc %p\n" | sort -n
#list_files
#choose files matching DARWIN_policy.*\.tar\.gz
#sort_by mdate/mtime
#choose latest
#/mnt/z/darwin/darwin_cofw_policies/DARWIN_policy-2022-07-04_0032.tar.gz
#unlink UserDataDocuments/Darwin_policy
#create UserDataDocuments/Darwin_policy
#send path to
#tar -xvzf __path__ --directory
#delete Network_objects.json, Standard_objects.json from SumELK
#select Network_objects.json, Standard_objects.json, copy to SumELK
def rename_darwin_transform_json():
    darwin_transform_json=Path("darwin_transform.json")
    target_string="old_darwin_transform.json"
    target = Path(target_string)
    if not target.exists():
        darwin_transform_json.rename(target_string)

#regex for finding snic_network_blabla.csv
def remove_snic_csv():
    snic_fil_path=project_dir/Path("snic_network_assignments_xxx.csv")
    abs_snic_fil_path=snic_fil_path.absolute()
    pttrn_snic=re.compile(abs_snic_fil_path.name)


    for x in project_dir.iterdir():
        if pttrn_snic.match(x.name):
            x.unlink()
    if Path(abs_snic_fil_path).exists():
        raise RuntimeError("%s still exists!" %(abs_snic_fil_path))
def replace_snic_csv():


# regex for finding darwin_ruleset.xlsx
def remove_ruleset_csv():
    drwn_ruleset_file_path=project_dir/Path("darwin_ruleset_unpacked_xxx.xlsx")
    abs_drwn_ruleset_file_path=drwn_ruleset_file_path.absolute()
    pttr_ruleset=re.compile(abs_drwn_ruleset_file_path.name)
    for x in project_dir.iterdir():
        if pttr_ruleset.match(x.name):
            x.unlink()
    if Path(abs_drwn_ruleset_file_path):
        raise RuntimeError("%s still exists!" % (abs_drwn_ruleset_file_path))

#[child.unlink() for child in Path("darwin_hits).listdir()]
def clear_darwin_hits():
