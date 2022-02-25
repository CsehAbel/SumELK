########## neu mit sysdb ################################################################################################################################################
########## process ip unique of all fw and seek new targets #############################################################################################################
########## neu mit sysdb ################################################################################################################################################

import pandas as pd
import numpy as np
import ipaddress as iplib #ip.
import glob
from my_functions import *
from datetime import datetime, date, time, timezone, timedelta
import time
import socket
import struct
import subprocess
import ipaddress
import re
import pyperclip

# check if port is open on the ip
def check_port(ip, port,timeout):
    import socket
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    a_socket.settimeout(timeout) #Timeout in seconds
    location=(ip,port)
    result_of_check = a_socket.connect_ex(location)
    a_socket.close()
    if result_of_check == 0:
        return("open")
    else:
        return("closed")

#from my_functions import *

d = date.today() #- timedelta(0)  #today #today = d.isoformat()
y = date.today() - timedelta(1) #yesterday#yesterday = y.isoformat()

today = d.isoformat()
yesterday = y.isoformat()

############################### Datum verschieben ###########
yesterday = '2022-02-06'
today     = '2022-02-07'
############################### Datum verschieben ###########

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

#get latest snic-db, add binary values
snicfiles=glob.glob(r'D:\snic\*-snic_ip_network_assignments.csv')
print('load latest SNIC file: ' + snicfiles[-1])
snic = pd.read_csv(snicfiles[-1],sep = ';',encoding = "latin-1", dtype = 'str')
snic['ip_base_bin'] = snic['IP-net-base'].apply(lambda x: ip2int(x))
snic['ip_top_bin'] = snic['IP-net-top'].apply(lambda x: ip2int(x))
snic.replace(np.NaN,"", inplace = True)
#get latest ipman table from d:\tmp\ipnet.csv
ipman = pd.read_csv(r'D:\tmp\ipnet.csv',delimiter=';', encoding='cp1252' )
ipman = ipman.replace('&sect;','&')
ipman['ip_base_bin'] = ipman['ip_net_base'].apply(lambda x: ip2int(x))
ipman['ip_top_bin'] = ipman['ip_net_top'].apply(lambda x: ip2int(x))
ipman.replace(np.NaN,"-", inplace = True) 
#ipman[(ipman['vpn_name']!=ipman['snic_vpn_name']) & (ipman['snic_status']!='-')] # vpn_name != snic_vpn_name
#ipman[(ipman['snic_vpn_name']=='Siemens VPN')] #entries with Siemens VPN

def get_ip_range(istr):
    ipbin = ip2int(istr)
    ip_range_row = snic.loc[(ipbin >= snic['ip_base_bin'] ) & (ipbin <= snic['ip_top_bin']), ['IP range/CIDR']]
    if ip_range_row.empty == True:
        ip_range = 'no SNIC-DB entry'
    else:
        ip_range = ip_range_row.iat[0,0]
    return ip_range

def get_ip_range_ipman(istr):
    ipbin = ip2int(istr)
    ip_range_row = ipman.loc[(ipbin >= ipman['ip_base_bin'] ) & (ipbin <= ipman['ip_top_bin']), ['net_address']]
    if ip_range_row.empty == True:
        ip_range = 'no IPMAN entry'
    else:
        ip_range = ip_range_row.iat[0,0]
    return ip_range


def get_latest_sysdb():
    files=glob.glob(r'D:\php\sysdb*.gz')
    print('load latest sysdb file: ' + files[-1])
    sysdb = pd.read_csv(files[-1],sep = ';',encoding = "utf-8", dtype = 'str')
    sysdb.replace(np.NaN,"", inplace = True)
    return sysdb

def iplc():
    ipl = pd.read_clipboard(header = None, names=['ip'] , sep = '\b') #dummy separator to keep 1 column
    ipl = ipl.ip.str.extract('(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', expand=True)#clean IP
    ipl = pd.merge(left = ipl, right=sysdb, how='left', left_on='ip', right_on='ip')
    ipl.to_clipboard(index = None)

def iplcshort():
    ipl = pd.read_clipboard(header=None,names=['ip'])
    ipl = pd.merge(left = ipl, right=sysdb[['ip','c','l','info']], how='left', on='ip')
    ipl.to_clipboard(index = None)

def ipldel():
    global sysdb
    ipl_to_del = pd.read_clipboard(header=None,names=['ip'])
    sysdb = sysdb[~sysdb.ip.isin(ipl_to_del.ip)]

def pol():
    ipl = pd.read_clipboard(header=None,names=['ip'])
    ipl = ipl.ip.str.extract('(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', expand=True)#clean IP
    ipl = pd.merge(left = ipl, right=sysdb, how='left', left_on='ip', right_on='ip')
    ipl = ipl[['dns','ip','info']]
    ipl.to_clipboard(index = None)

def dnsc():
    dnsl = pd.read_clipboard(header=None,names=['dns'],sep = '#')
    for index,row in dnsl.iterrows():
        dns_str = row['dns'].replace(' ', '').lower()
        if '|' in dns_str:
            x = dns_str.split("|")
            for y in x:
                new_row = {'dns':y}
                dnsl = dnsl.append(new_row, ignore_index=True)
        if ',' in dns_str:
            x = dns_str.split(",")
            for y in x:
                new_row = {'dns':y}
                dnsl = dnsl.append(new_row, ignore_index=True)
    
    dnslnew = dnsl[~dnsl['dns'].str.contains('\|')]
    dnslnew = dnslnew[~dnslnew['dns'].str.contains(',')]
    dnslnew = dnslnew.drop_duplicates(subset=['dns'], keep='first')
    print(dnslnew)
    dnslnew['dns'].to_csv(r'\\defthw99m5bsrv.ad001.siemens.net\powershell\dns.txt', index = False, header = False)
    cmd = 'Invoke-Command -ComputerName defthw99m5bsrv.ad001.siemens.net -FilePath D:\powershell\pydns2ip.ps1'
    completed = subprocess.run(["powershell", "-Command", cmd])
    dnslx = pd.read_csv(r'\\defthw99m5bsrv.ad001.siemens.net\powershell\ip.csv',sep=';')
    dnslx = dnslx[dnslx['IP']!='IP n/a']
    export_columns = ['IP', 'DNS']
    dnslx.to_clipboard(index = None,columns = export_columns)
    print(dnslx)
    print(dnslx.DNS.str.cat(sep='|'))

def ip2dns(): #defthw99m5bsrv.ad001.siemens.net 139.23.160.99
    ipl = pd.read_clipboard(header=None,names=['ip'])
    ipl.to_csv(r'\\defthw99m5bsrv.ad001.siemens.net\powershell\ip.txt', index = False, header = False)
    cmd = 'Invoke-Command -ComputerName DEFTHW99M5BSRV -FilePath d:\powershell\pyip2dns.ps1'
    completed = subprocess.run(["powershell", "-Command", cmd])
    #\\defthw99m5bsrv.ad001.siemens.net\powershell\dns.csv
    dns = pd.read_csv(r'\\defthw99m5bsrv.ad001.siemens.net\powershell\dns.csv',sep=';') #get dns after running get-dns-by-ips.ps1
    print(dns)
    dns.to_clipboard(index = None, header = None)

def snicc():
    ipl = pd.read_clipboard(header=None,names=['ip'], sep = "\b") #dummy separator\b 
    ipl = ipl.ip.str.extract('(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', expand=True) # clean IP input
    ipl['ip_cidr'] = ipl.apply(lambda x: get_ip_range(x['ip']) , axis=1) # get snic values
    ipl = pd.merge(left = ipl, right=snic, how = 'left', left_on='ip_cidr', right_on='IP range/CIDR')
    del (ipl['ip_cidr'])
    ipl.to_clipboard(index = None)

def snics():
    ipl = pd.read_clipboard(header=None,names=['ip'], sep = "\b") #dummy separator\b 
    ipl = ipl.ip.str.extract('(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', expand=True) # clean IP input
    ipl['ip_cidr'] = ipl.apply(lambda x: get_ip_range(x['ip']) , axis=1) # get snic values
    ipl = pd.merge(left = ipl, right=snic, how = 'left', left_on='ip_cidr', right_on='IP range/CIDR')
    del (ipl['ip_cidr'])
    print(ipl[['ip','Country','Location','VPN name','IP range/CIDR','SNX Service Point ID','Comment']])
    ipl.to_clipboard(index = None)

def ipmanc():
    ipl = pd.read_clipboard(header=None,names=['ip'])
    ipl['ip_cidr'] = ipl.apply(lambda x: get_ip_range_ipman(x['ip']) , axis=1)
    ipl = pd.merge(left = ipl, right=ipman, how = 'left', left_on='ip_cidr', right_on='net_address')
    del (ipl['ip_cidr'])
    ipl.to_clipboard(index = None)

def portc():
    pl = pd.read_clipboard(header=None,names=['PORT','STATE','SERVICE'])
    pl['p'] = pl.apply(lambda x: x['PORT'].split("/")[1] + '_' + x['PORT'].split("/")[0] + ',',axis=1)
    pl.to_clipboard(index = None)

def t2l():
    import pyperclip
    pl = pd.read_clipboard(header = None, names=['protocol','port'] , sep = ' ') #dummy separator to keep 1 column
    pl['pp'] = pl.apply(lambda x: x.protocol + '_' + str(x.port), axis = 1)
    #print(pl)
    rstr=(pl.pp.str.cat(sep=',')+',').lower()
    pyperclip.copy(rstr)
    print(rstr)

def l2t():
    import pyperclip
    pl_str = pyperclip.paste()
    if (pl_str[-1]==','):
        pl_str = pl_str[0:-1]
    pl_str.lower()
    #pl_str.split(',')
    pll = {'prot_port':pl_str.split(',')}
    pl = pd.DataFrame(pll,columns=['prot_port'])
    pl.replace(regex={r'_': ' ' , r',$':''}, inplace = True)
    pl['prot_port'] = pl['prot_port'].str.upper()
    #p1 = pd.DataFrame(pl_str,columns=['port'])
    #pyperclip.copy(str(pl))
    pl.to_clipboard(index = None, header=None)
    print(pl)

def sysdbf(findstr):
    global sysdb
    print(sysdb[sysdb['info'].str.contains(findstr,case = False)])

#
'''
def iprc():
    import pyperclip
    import ipaddress
    pl = pd.read_clipboard(header = None, names=['start_ip','stop_ip'] , sep = '-')
    print(pl)
    start_ip = ipaddress.IPv4Address('137.223.66.67')
    end_ip = ipaddress.IPv4Address('137.223.66.72')
    for ip_int in range(int(start_ip), int(end_ip)+1):
        print(ipaddress.IPv4Address(ip_int))



import re 
  
with open('C:/Users/user/Desktop/New Text Document.txt') as fh: 
   fstring = fh.readlines() 
  
pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') 
  
lst=[] 
  
for line in fstring: 
   lst.append(pattern.search(line)[0]) 
  
print(lst) 

'''


if not 'sysdb' in dir():
    sysdb = get_latest_sysdb()



log_analysis_dir_se         = 'D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\'
log_analysis_dir_express    = 'D:\\compusafe\\Kunden\\mobility\\00_firewall_cofw\\analysis\\'
log_analysis_dir_sppal      = 'D:\\compusafe\\Kunden\\IC_MOL_LAS_Goliath_David\\Firewall\\analysis\\firewall_logs\\'
log_analysis_dir_blizzard   = 'D:\\compusafe\\Kunden\\Blizzard\\cofw_blizzard\\analysis_blizzard\\'

ip_unique_yesterday_se_red	 		= log_analysis_dir_se + yesterday + '.log_export_red.txt.src-dst.csv.unique.ips.csv.gz'
ip_unique_yesterday_se_blue         = log_analysis_dir_se + yesterday + '.log_export_blue.txt.src-dst.csv.unique.ips.csv.gz'		
ip_unique_yesterday_express_red	    = log_analysis_dir_express + yesterday + '.log_export_red.txt.src-dst.csv.unique.ips.csv.gz'
ip_unique_yesterday_express_blue	= log_analysis_dir_express + yesterday + '.log_export_blue.txt.src-dst.csv.unique.ips.csv.gz'
ip_unique_yesterday_sppal			= log_analysis_dir_sppal + yesterday + '.log_export.txt.src-dst.csv.unique.ips.csv.gz'
ip_unique_yesterday_blizzard_red	= log_analysis_dir_blizzard + yesterday + '.log_export_red.txt.src-dst.csv.unique.ips.csv.gz'
ip_unique_yesterday_blizzard_blue	= log_analysis_dir_blizzard + yesterday + '.log_export_blue.txt.src-dst.csv.unique.ips.csv.gz'
ip_awk								= 'D:\\tmp\\x\\' + yesterday + '_ip_awk.csv'
ip_zzz								= 'D:\\tmp\\x\\' + yesterday + '_ip_zzz.csv'

ip_unique0 = pd.read_csv(ip_unique_yesterday_se_red,delimiter=';',encoding = 'cp1252',error_bad_lines=False,warn_bad_lines=True, usecols=['IP','normed IP','Country', 'Location', 'Comment'])
ip_unique1 = pd.read_csv(ip_unique_yesterday_se_blue, sep = ';', encoding = 'cp1252', error_bad_lines = False, warn_bad_lines=True, usecols=['IP','normed IP', 'Country', 'Location', 'Comment'])
ip_unique2 = pd.read_csv(ip_unique_yesterday_express_red,delimiter=';',encoding = 'cp1252',error_bad_lines=False,warn_bad_lines=True, usecols=['IP','normed IP', 'Country', 'Location', 'Comment'])
#ip_unique2[ip_unique2['IP'].str.contains('^10\.14')]
#ip_unique2.replace(np.NaN,'-',inplace=True)
#ip_unique2[ip_unique2['Comment'].str.contains('(Azur|cloud|AWS)',case=False)] #suche cloud targets (Achtung nicht Shawson Drive!)
ip_unique3 = pd.read_csv(ip_unique_yesterday_express_blue,delimiter=';',encoding = 'cp1252',error_bad_lines=False,warn_bad_lines=True, usecols=['IP', 'normed IP','Country', 'Location', 'Comment'])
ip_unique4 = pd.read_csv(ip_unique_yesterday_sppal,delimiter=';',encoding = 'cp1252',error_bad_lines=False,warn_bad_lines=True, usecols=['IP', 'normed IP','Country', 'Location', 'Comment'])


#ip_unique = pd.concat([ip_unique0,ip_unique1],ignore_index=True)
#ip_unique = pd.concat([ip_unique0,ip_unique2,ip_unique3,ip_unique4],ignore_index=True)
ip_unique = pd.concat([ip_unique0,ip_unique1,ip_unique2,ip_unique3,ip_unique4],ignore_index=True)
#ip_unique = pd.concat([ip_unique0,ip_unique2,ip_unique3,ip_unique4],ignore_index=True)

ip_unique = ip_unique.drop_duplicates(subset=['normed IP'])
ip_unique.sort_values('normed IP',inplace = True)
ip_unique = ip_unique.fillna('no SNIC-DB entry')

ip_unique.to_csv(ip_awk,sep=';',encoding = 'cp1252',index = None)

#sysdb = get_latest_sysdb()
#sysdb = pd.read_csv(r'D:\php\sysdb_'+yesterday+'.gz', delimiter=';',dtype='str',encoding='utf-8')
#sysdb = pd.read_csv(r'D:\php\sysdb_'+today+'.gz', delimiter=';',dtype='str',encoding='utf-8')

ip_unique_check = pd.merge(left=ip_unique, right=sysdb, how='left', left_on='IP', right_on='ip')
ip_unique_check = ip_unique_check.fillna('zzz-new')
#ip_unique_check = ip_unique_check.sort_values('normed IP')
#ip_unique_check=ip_unique_check[(ip_unique_check['info']=='zzz-new') & (ip_unique_check['c !='no SNIC-DB entry found')]
ip_unique_check=ip_unique_check[(ip_unique_check['ip']=='zzz-new') & (ip_unique_check['Country']!='no SNIC-DB entry found')]
from my_functions import *
#add new column with auto_comment
ip_unique_check['zzz']=ip_unique_check['Comment'].apply(auto_comment)
ip_unique_check.to_csv(ip_zzz,sep=';',encoding = 'cp1252',index = None)
ip_unique_check['IP'].to_csv(r'\\139.23.160.99\d$\powershell\ip.txt', index = False, header = False)

###################################################################################################################
#           Achtung vorher auf Server get-dns-by-ips.ps1 laufen lassen
import subprocess
#cmd = 'Invoke-Command -ComputerName DEFTHW99M5BSRV -FilePath d:\powershell\get-dns-by-ips.ps1'
cmd = 'Invoke-Command -ComputerName DEFTHW99M5BSRV -FilePath d:\powershell\pyip2dns.ps1'
completed = subprocess.run(["powershell", "-Command", cmd])
####################################################################################################################

dns = pd.read_csv(r'\\139.23.160.99\d$\powershell\dns.csv',sep=';') #get dns after running get-dns-by-ips.ps1
ip_unique_check['dns'] = dns['DNS'].values  # add column of \\139.23.160.99\d$\powershell\dns.csv to ip_unique_check
ip_unique_check['sys_type'] = ip_unique_check['zzz']
del ip_unique_check['zzz']
ip_unique_check['last_modified']=today
ip_unique_check['ip']=ip_unique_check['IP']
ip_unique_check['c']=ip_unique_check['Country']
ip_unique_check['l']=ip_unique_check['Location']
ip_unique_check['snic_comment']=ip_unique_check['Comment']
ip_unique_check.drop(['IP'],axis=1,inplace=True)
ip_unique_check.drop(['normed IP'],axis=1,inplace=True)
ip_unique_check.drop(['Country'],axis=1,inplace=True)
ip_unique_check.drop(['Location'],axis=1,inplace=True)
ip_unique_check.drop(['Comment'],axis=1,inplace=True)
ip_unique_check = ip_unique_check.reset_index(drop=True)
ip_unique_check.replace(to_replace = 'zzz-new', value = '', inplace = True)
ip_unique_check.replace(to_replace = 'DNS n/a', value = '', inplace = True)
ip_unique_check.replace(to_replace = 'NaN', value = '', inplace = True)

ip_unique_check = ip_unique_check[ip_unique_check['ip'] != 'no SNIC-DB entry']

#################################### SNIC Abgleich ############################################
#startTime = time.time()
#ip_unique_check['ip_cidr'] = ip_unique_check['ip'].apply(lambda x: get_ip_range(str(x['ip']))) 
ip_unique_check['ip_cidr'] = ip_unique_check.apply(lambda x: get_ip_range(x['ip']) , axis=1)
#executionTime = (time.time() - startTime)
#print('Execution time in seconds: ' + str(executionTime))
#################################### SNIC Abgleich ############################################
#####zurück999
ip_unique_check = pd.merge(left=ip_unique_check, right=snic, left_on='ip_cidr', right_on='IP range/CIDR')
ip_unique_check['c'] = ip_unique_check['Country']
ip_unique_check['l'] = ip_unique_check['Location']
ip_unique_check['vpn_name'] = ip_unique_check['VPN name']

ip_unique_check['region'] = ip_unique_check.apply(lambda x: str(x['fw_object_name']).split("_")[0],axis=1)    
ip_unique_check['hostname'] = ip_unique_check.apply(lambda x: x['dns'].split(".")[0],axis=1)    
ip_unique_check['domain'] = ip_unique_check.apply(lambda x: x['dns'].replace(str(x['hostname']),'')[1:],axis=1)

#del (ip_unique_check['fw_object_name'])
del (ip_unique_check['Country'])
del (ip_unique_check['Location'])
del (ip_unique_check['Possessor'])
del (ip_unique_check['TLU-(Maintainer)'])
del (ip_unique_check['Routing Domain'])
del (ip_unique_check['IP-net-base'])
del (ip_unique_check['IP-net-top'])
del (ip_unique_check['Range'])
del (ip_unique_check['CIDR'])
del (ip_unique_check['VPN name'])
del (ip_unique_check['Status'])
del (ip_unique_check['Usage IPINS'])
del (ip_unique_check['Usage Softguard'])
del (ip_unique_check['Consumer'])
del (ip_unique_check['Technical Contact'])
del (ip_unique_check['USSM'])
del (ip_unique_check['Comment'])
del (ip_unique_check['Last docu change date'])
del (ip_unique_check['Last IP-address change date'])
del (ip_unique_check['Last SIAM docu change IDs'])
del (ip_unique_check['Last SIAM IP-address change ID'])
del (ip_unique_check['SNX Service Point ID'])
del (ip_unique_check['SNX WAN service name'])
del (ip_unique_check['SNX Connects-to'])
del (ip_unique_check['SNX WAN service provider'])
del (ip_unique_check['Network Zone'])
del (ip_unique_check['Type'])
del (ip_unique_check['IAP Name'])
del (ip_unique_check['IAP Purpose'])
del (ip_unique_check['IAP Unit'])
del (ip_unique_check['IAP Security Responsible Person'])
del (ip_unique_check['IAP Comment'])
del (ip_unique_check['norm_IP'])
del (ip_unique_check['potential router ip'])
del (ip_unique_check['last useable IP'])
del (ip_unique_check['IP range/CIDR'])
del (ip_unique_check['mask'])
del (ip_unique_check['fw_object_name'])
del (ip_unique_check['ip_base_bin'])
del (ip_unique_check['ip_top_bin'])

ip_unique_check['info'] = ip_unique_check['sys_type'] + '|' + ip_unique_check['dns'] + '|' + ip_unique_check['corpflag'] + '|' + ip_unique_check['info_extra'] + '|' + ip_unique_check['managed_by_mail'] + '|' + ip_unique_check['description'] + '|' + ip_unique_check['snic_comment'] + '|' + ip_unique_check['ip_cidr'] + '|' + ip_unique_check['c'] + '|' + ip_unique_check['l']

#del (ip_unique_check['zzz'])
ip_unique_check.to_csv(r'D:\php\unique_ips_new_'+today+'.gz',sep =';',encoding='cp1252',index=False)
sysdb = pd.concat([sysdb,ip_unique_check],ignore_index=True)

#today='2021-01-17'
#yesterday='2021-01-16'
sysdb = sysdb.replace("nan|nan","")
sysdb = sysdb.replace(np.NaN,"")

sysdb['info'] = sysdb['sys_type'] + '|' + sysdb['dns'] + '|' + sysdb['corpflag'] + '|' + sysdb['info_extra'] + '|' + sysdb['managed_by_mail'] + '|' + sysdb['description'] + '|' + sysdb['snic_comment'] + '|' + sysdb['ip_cidr'] + '|' + sysdb['c'] + '|' + sysdb['l']
sysdb

sysdb.to_csv(r'D:\php\sysdb_'+today+'.gz',sep =';',encoding='utf-8',index=False)



################################################################################################################
################################################################################################################
#compute grey rule mit dem obigen Ergebnis aus sysdb
################################################################################################################
################################################################################################################
import pandas as pd
import numpy as np
import ipaddress as iplib

from datetime import datetime, date, time, timezone, timedelta
import time

d = date.today()
today = d.isoformat()
today
y = date.today() - timedelta(1)
yesterday = y.isoformat()
yesterday

#today='2021-02-28'
#yesterday='2021-02-27'
#yesterday = '2021-06-02'
#today     = '2021-07-03'

#sysdb = pd.read_csv(r'D:\php\sysdb_'+today+'.gz',delimiter=';',encoding='utf-8',dtype='str')

import ipaddress as iplib

log_analysis_dir_se         = 'D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\'
log_analysis_dir_express    = 'D:\\compusafe\\Kunden\\mobility\\00_firewall_cofw\\analysis\\'
log_analysis_dir_sppal      = 'D:\\compusafe\\Kunden\\IC_MOL_LAS_Goliath_David\\Firewall\\analysis\\firewall_logs\\'
log_analysis_dir_blizzard   = 'D:\\compusafe\\Kunden\\Blizzard\\cofw_blizzard\\analysis_blizzard\\'

#sysdb = pd.read_csv(r'd:\php\sysdb_'+today+'.gz', sep = ';', encoding = 'utf-8', dtype = 'str')


#D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-01-01.log_export_red.txt.src-dst.csv.gz
log_file_yesterday = log_analysis_dir_se + yesterday + '.log_export_red.txt.src-dst.csv.gz'
ip_unique_yesterday_red = log_analysis_dir_se + yesterday + '.log_export_red.txt.src-dst.csv.unique.ips.csv.gz'
#ip_unique_yesterday_red= y.strftime('D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\%Y-%m-%d.log_export_red.txt.src-dst.csv.unique.ips.csv.gz')
#snic_today='D:\\snic\\'+today.replace('-','')+'-snic_ip_network_assignments.csv'
#snic=pd.read_csv(snic_today,delimiter=';', encoding='latin_1',engine='python' )
log = pd.read_csv(log_file_yesterday,delimiter=';')
log.sort_values(by="connects",ascending=False,inplace=True)
log.replace(np.NAN,'',inplace = True)

#log[log['ports'].str.contains('tcp_8080,')] #seek ports in Log File
#log[(log['ports'].str.contains('tcp_8080,')) & (log['rule_name']=='s_saperion')]
#log[(log['ports'].str.contains('tcp_8080,')) & (log['rule_name']=='wuser_3056')]
#log[(log['rule_name']=='s_saperion') & (~log['orig'].str.contains('DE')) & (log['ports'].str.contains('tcp_8080,'))]
#grey = log[(log['rule_name'].str.contains('^grey')) &(log['ports'].str.contains('tcp_22'))] #search grey tcp_22
#log[log['rule_name']=='Cleanup rule']
#log[log['rule_name'].str.contains('^grey')]
#log[log['rule_name']=='grey_black2blue']



#grey = log[log['rule_name'].str.contains('^grey_red2blue')] #split in 2 greyrules

grey = log[log['rule_name'].str.contains('^Cleanup rule')] #split in 2 greyrules

#log_grey_black2bluegrey = log[log['rule_name'].str.contains('^grey_black2blue')] #split in 2 greyrules zurück6

grey = grey.sort_values(by="connects",ascending=False)
ip_unique_red = pd.read_csv(ip_unique_yesterday_red,delimiter=';',encoding = 'cp1252',error_bad_lines=False,warn_bad_lines=True, usecols=['IP','normed IP','Country', 'Location', 'Comment'])
ip_unique=ip_unique_red.drop_duplicates(subset=['normed IP'])
#del ip_unique['color']
#del ip_unique['Status']
#del ip_unique['Info']
ip_unique = ip_unique.sort_values(by=['normed IP'])

grey_log_merged = pd.merge(left=grey, right=ip_unique, left_on='src', right_on='IP')
grey_log_merged=grey_log_merged.rename(columns={"normed IP": "src_normed_ip", "Country": "src_c", "Location": "src_l", "Comment": "src_comment"})
del grey_log_merged['IP']
grey_log_merged = pd.merge(left=grey_log_merged, right=ip_unique, left_on='dst', right_on='IP')
grey_log_merged=grey_log_merged.rename(columns={"normed IP": "dst_normed_ip", "Country": "dst_c", "Location": "dst_l", "Comment": "dst_comment"})
del grey_log_merged['IP']
#merge grey src with sysdb
grey_log_merged = pd.merge(left=grey_log_merged, right=sysdb, left_on='src', right_on='ip')
del grey_log_merged['region']
del grey_log_merged['ip_cidr']
del grey_log_merged['direction']
del grey_log_merged['tcp']
del grey_log_merged['udp']
del grey_log_merged['icmp']
del grey_log_merged['rule']
del grey_log_merged['rule_name']
del grey_log_merged['accepted']
del grey_log_merged['acceptance']
del grey_log_merged['src_normed_ip']
del grey_log_merged['src_comment']
del grey_log_merged['dst_normed_ip']
del grey_log_merged['dst_comment']
del grey_log_merged['ip']
del grey_log_merged['dns']
del grey_log_merged['c']
del grey_log_merged['l']
del grey_log_merged['sys_type']
del grey_log_merged['corpflag']
del grey_log_merged['info_extra']
del grey_log_merged['mac']
del grey_log_merged['macprovider']
del grey_log_merged['hostname']
del grey_log_merged['domain']
del grey_log_merged['host_dn']
del grey_log_merged['managedby']
del grey_log_merged['managedbygid']
del grey_log_merged['managed_by_mail']
del grey_log_merged['os']
del grey_log_merged['description']
del grey_log_merged['last_modified']
del grey_log_merged['owner']
del grey_log_merged['snic_comment']
del grey_log_merged['vpn_name']
grey_log_merged = grey_log_merged.rename(columns={"info": "src_info"})
#merge src with sxx
grey_log_merged = pd.merge(left=grey_log_merged, right=sysdb, left_on='dst', right_on='ip')

del grey_log_merged['ip']
del grey_log_merged['dns']
del grey_log_merged['c']
del grey_log_merged['l']
del grey_log_merged['sys_type']
del grey_log_merged['corpflag']
del grey_log_merged['info_extra']
del grey_log_merged['mac']
del grey_log_merged['macprovider']
del grey_log_merged['hostname']
del grey_log_merged['domain']
del grey_log_merged['host_dn']
del grey_log_merged['managedby']
del grey_log_merged['managedbygid']
del grey_log_merged['managed_by_mail']
del grey_log_merged['os']
del grey_log_merged['description']
del grey_log_merged['last_modified']
del grey_log_merged['owner']
del grey_log_merged['snic_comment']
del grey_log_merged['region']
del grey_log_merged['ip_cidr']
del grey_log_merged['vpn_name']
grey_log_merged = grey_log_merged.rename(columns={"info": "dst_info"})

grey_log_merged = grey_log_merged.convert_dtypes()

from my_functions import *
import re
import time

############################################################
startTime = time.time()
grey_log_merged['category']=grey_log_merged[['src','src_info','dst','dst_info','ports']].apply(lambda x: autoanalysis(x['src'],x['src_info'],x['dst'],x['dst_info'],x['ports']),axis=1)
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))
############################################################

grey_log_merged.sort_values('connects', ascending = False, inplace = True)
grey_log_merged = grey_log_merged[['src','src_c','src_l','src_info','dst','dst_c','dst_l','dst_info','connects','category','ports','orig']]
export_columns = ['src', 'src_c', 'src_l', 'src_info', 'dst', 'dst_c', 'dst_l', 'dst_info', 'connects', 'category', 'ports', 'orig']
grey_log_merged.to_csv('D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\'+yesterday+'_grey_log.csv.gz', sep = ';', columns = export_columns, index = False)

#grey_log_merged=pd.read_csv('D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\'+yesterday+'_grey_log.csv.gz', sep = ';' ,encoding = 'utf-8')
#grey_log_merged=pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-04-08_grey_log.csv.gz', sep = ';' )
#grey_log_merged.groupby('dst')['connects'].sum()
#grey_log_merged.groupby('dst')['connects'].sum().sum()
#grey_log_merged.groupby('dst')['connects'].sum().max()
check = grey_log_merged[['dst','connects','category','dst_info','ports']]
check = check.groupby('dst',as_index=False).agg({'connects':'sum'})
check=check.sort_values('connects', ascending = False)
check['connects'].max()
#check=check.sort_values('connects')
#check.head(50)
check=pd.merge(left=check, right=sysdb, how='left', left_on='dst', right_on='ip').drop_duplicates(subset=['dst'])
#check.head(50)


#del (check['connects'])
del (check['ip'])
#del (check['dns'])
del (check['c'])
del (check['l'])
del (check['sys_type'])
del (check['corpflag'])
del (check['info_extra'])
#del (check['info'])
del (check['mac'])
del (check['macprovider'])
del (check['hostname'])
del (check['domain'])
del (check['host_dn'])
del (check['managedby'])
del (check['managedbygid'])
del (check['managed_by_mail'])
del (check['os'])
del (check['description'])
del (check['region'])
del (check['last_modified'])
del (check['owner'])
del (check['snic_comment'])
del (check['ip_cidr'])
del (check['vpn_name'])


check=check.replace('nan|nan','')
check=check.replace(np.NaN,'-')

check.head(55)
check.to_csv(log_analysis_dir_se + yesterday + '_top-ip-file.csv.gz', sep = ';') #, encoding = 'cp1252')

#grey_log_merged[grey_log_merged['dst']=='139.21.146.77'].T.to_clipboard()#Ausgabe für eine IP
#check = pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-02-08_top-ip-file.csv.gz', sep = ';', encoding = 'cp1252')

#grey_log_merged[(grey_log_merged['ports'].str.contains('udp_5246,')) & (grey_log_merged['dst'] == '141.29.66.37')]
#grey_log_merged[(grey_log_merged['src'] == '139.24.188.250') | (grey_log_merged['src'] == '139.24.188.251')]['connects'].sum() # scanners

######################### end of greyrule analysis #####################################################
######################### end of greyrule analysis #####################################################


######################### filter grey rule results #####################################################
######################### filter grey rule results #####################################################

#check[check['info'].str.contains('^office')]#.to_clipboard(sep = '\t', index = None)
#check[check['info'].str.contains('^PC')].head(50)#.to_clipboard(sep = '\t', index = None)

se_servers = grey_log_merged[grey_log_merged['dst_info'].str.contains('(energy|pg\.)')].drop_duplicates(subset=['dst'])[['dst','dst_info','connects','ports']]
if se_servers.shape[0]!=0:
    se_servers.to_csv('d:\\tmp\\ '+ yesterday + ' se_servers.csv', sep = ';', encoding = 'cp1252', index = None)
    se_servers
#
#grey_log_merged[grey_log_merged['dst'].str.contains('163.242.108.94')]#.connects.sum()

#grey_log_merged[grey_log_merged['dst'].str.contains('^157.163.152.7$') & grey_log_merged['ports'].str.contains('tcp_5044,')]

sms_server_traffic = grey_log_merged[grey_log_merged['category'].str.contains("sw_distribution") & grey_log_merged['dst_info'].str.contains("^server\|sms\|")]
if sms_server_traffic.shape[0]!=0:
    sms_server_traffic
    sms_server_traffic.connects.sum()
    sms_server_unique = sms_server_traffic.drop_duplicates(subset=['dst'])
    sms_server_unique.to_excel('d:\\tmp\\ ' + yesterday + '_sms_server_unique.xlsx', sheet_name = 'white_sms_server' , encoding = 'cp1252', columns = ['dst','dst_info'])
    sms_server_unique

#net view \\140.231.210.113 /all >> d:\tmp\fs-check.txt 
#dir file.xxx 1> output.msg 2>&1

# av server
av_server_traffic = grey_log_merged[grey_log_merged['category'].str.contains("^av$") & grey_log_merged['dst_info'].str.contains("^server\|av\|")]
if av_server_traffic.shape[0]!=0:
    av_server_traffic
    av_server_traffic.connects.sum()
    av_server_unique = av_server_traffic.drop_duplicates(subset=['dst'])
    av_server_unique
    av_server_unique.to_excel('d:\\tmp\\av_server_unique_' + yesterday + '.xlsx', sheet_name = 'white_av_server' , encoding = 'cp1252', columns = ['dst','dst_info'])


#dhcp_server = grey_log_merged[grey_log_merged['ports'].str.contains("_6[7-9],")].drop_duplicates(subset=['dst']).sort()

dhcp_server_traffic = grey_log_merged[grey_log_merged['ports'].str.contains("_67,")].drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
if dhcp_server_traffic.shape[0]!=0:
    dhcp_server_traffic
    dhcp_server_traffic.connects.sum()
    dhcp_server_unique = dhcp_server_traffic.drop_duplicates(subset=['dst'])
    dhcp_server_unique
    dhcp_server_unique.to_excel('d:\\tmp\\' + yesterday + '_dhcp_server_unique.xlsx', sheet_name = 'white_dhcp_server' , encoding = 'cp1252', columns = ['dst','dst_info'])

#
ssh_traffic = grey_log_merged[grey_log_merged['ports'].str.contains("tcp_22,")]
if ssh_traffic.shape[0]!=0:
    ssh_traffic
    ssh_traffic.to_csv('d:\\tmp\\grey_ssh_traffic_' + yesterday + '.csv',index = None, sep = ';', encoding = 'cp1252')
    ssh_traffic_unique = ssh_traffic.drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
    ssh_traffic_unique
#
rdp_traffic = grey_log_merged[grey_log_merged['ports'].str.contains("(tc|ud)p_3389,")]
if rdp_traffic.shape[0]!=0:
    rdp_traffic
    rdp_traffic.to_csv(r'd:\\tmp\\grey_rdp_traffic_' + yesterday + '.csv',index = None, sep = ';', encoding = 'cp1252')
    rdp_traffic_unique = rdp_traffic.drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
    rdp_traffic_unique
#
#grey vnc port 5800 5900
vnc_traffic = grey_log_merged[grey_log_merged['ports'].str.contains("tcp_5[8-9]0[0-9],")].drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
if vnc_traffic.shape[0]!=0:
    vnc_traffic
    vnc_traffic.to_csv(r'd:\\tmp\\grey_vnc_traffic_' + yesterday + '.csv',index = None, sep = ';', encoding = 'cp1252')
    vnc_traffic_unique = vnc_traffic.drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
    vnc_traffic_unique

# License Server
license_traffic = grey_log_merged[grey_log_merged['dst_info'].str.contains("license")].drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
if license_traffic.shape[0]!=0:
    license_traffic
    license_traffic.to_csv(r'd:\\tmp\\grey_license_traffic_' + yesterday + '.csv',index = None, sep = ';', encoding = 'cp1252')
    license_traffic_unique = license_traffic.drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
    license_traffic_unique

#oms_print
oms = grey_log_merged[grey_log_merged['dst_info'].str.contains("\|oms\|")].drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
if oms.shape[0]!=0:
    oms
    oms.to_csv(r'd:\\tmp\\grey_oms_print_traffic_' + yesterday + '.csv',index = None, sep = ';', encoding = 'cp1252')

#storage
#grey_log_merged[grey_log_merged['category'].str.contains("storage")].connects.sum()
storage = grey_log_merged[grey_log_merged['category'].str.contains("storage")].drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
if storage.shape[0]!=0:
    storage
    storage.to_csv('d:\\tmp\\grey_storage_traffic_' + yesterday + '.csv',index = None, sep = ';', encoding = 'cp1252')

#router
router = grey_log_merged[grey_log_merged['dst_info'].str.contains("^router\|")].drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
if router.shape[0]!=0:
    router
#
#pg servers
pg_servers = grey_log_merged[grey_log_merged['dst'].str.contains("\.pg\.")].drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
if pg_servers.shape[0]!=0:
    pg_servers
    pg_servers.to_csv('d:\\tmp\\pg_servers_' + yesterday + '.csv',index = None, sep = ';', encoding = 'cp1252')

#
#check printer if info begins with office
printers_unknown = grey_log_merged[grey_log_merged['ports'].str.contains('_9100,') & grey_log_merged['dst_info'].str.contains('^office')].drop_duplicates(subset=['dst'])
if printers_unknown.shape[0]!=0:
    printers_unknown.to_csv('d:\\tmp\\printers_unknown_' + yesterday + '.csv',sep=';', encoding = 'cp1252')
    printers_unknown
#grey_log_merged.to_clipboard(sep = '\t',index = None)

#sina_vpn_print
#
#sina_vpn = grey_log_merged[grey_log_merged['ports'].str.contains("udp_4500")].drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
#if sina_vpn.shape[0]!=0:
#    sina_vpn
#    sina_vpn.to_csv(r'd:\\tmp\\grey_sina_vpn_traffic_' + yesterday + '.csv',index = None, sep = ';', encoding = 'cp1252')
#
#
############### seek red src IPs scanning blue ###############################################################################################
#

src_scans = grey_log_merged['src'].value_counts()
src_scans_df = src_scans.reset_index()
src_scans_df = src_scans_df.rename(columns = {'src': 'frequency','index': 'src' })
src_scans_df
#grey_log_merged[grey_log_merged['src']=='161.218.67.24']['connects'].sum()
#grey_log_merged[grey_log_merged['src']=='139.24.188.251']['connects'].sum()
#grey_log_merged[grey_log_merged['src']=='161.218.67.24']['connects'].sum()
#grey_log_merged[grey_log_merged['src']=='10.222.138.207']['connects'].sum()

#dst_scans = grey_log_merged['dst'].value_counts()
#dst_scans_df = dst_scans.reset_index()
#dst_scans_df = dst_scans_df.rename(columns = {'dst': 'frequency','index': 'dst' })
#dst_scans_df
#grey_log_merged[grey_log_merged['dst']=='10.81.107.135']['connects'].sum()

###################################################################################################################
apps = grey_log_merged[grey_log_merged['category'].str.contains('^._app')]
#apps.to_csv('d:\\tmp\\' + yesterday + '_apps.csv', sep =';', encoding = 'cp1252')
apps.to_csv('d:\\tmp\\' + yesterday + '_apps.csv', sep =';')
apps

sap_servers_blue = grey_log_merged[grey_log_merged['ports'].str.contains('(tc|ud)p_32..,')]
sap_servers_blue
'''
5246
5247
13007
13009
'''

#### wlan-ap
grey_log_merged[grey_log_merged['ports'].str.contains('(tc|ud)p_5246,')]
grey_log_merged[grey_log_merged['ports'].str.contains('(tc|ud)p_5247,')]
grey_log_merged[grey_log_merged['ports'].str.contains('(tc|ud)p_13007,')]
grey_log_merged[grey_log_merged['ports'].str.contains('(tc|ud)p_13009,')]
#### voip 
grey_log_merged[grey_log_merged['ports'].str.contains('(tc|ud)p_5060,')]

################################################### end of special analysis #######################################
################################################### end of special analysis #######################################
################################################### end of special analysis #######################################

######################## check scans ##############################################################################
#grey_log_merged= pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-02-08_grey_log.csv.gz', sep = ';', encoding = 'cp1252')
#grey_log_merged = pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-02-21_grey_log.csv.gz', sep = ';', encoding = 'latin-1')
grey_log_merged.replace(np.NaN,'-', inplace=True)
check_scans_tcp_445 = grey_log_merged[grey_log_merged.ports.str.contains(',tcp_445,')]

scans = check_scans_tcp_445[check_scans_tcp_445.category.str.contains('scan')]
check_scans = scans.groupby('src',as_index=False).agg({'connects':'sum'})
check_scans = check_scans.sort_values('connects', ascending = False)
check_scans['connects'].max()
check_scans = pd.merge(left=check_scans, right=sysdb, how='left', left_on='src', right_on='ip').drop_duplicates(subset=['src'])
del check_scans['ip']
del check_scans['last_modified']
del check_scans['owner']
del check_scans['corpflag']
del check_scans['mac']
del check_scans['macprovider']
del check_scans['dns']
del check_scans['snic_comment']
del check_scans['info_extra']
del check_scans['hostname']
del check_scans['domain']
del check_scans['managedby']
del check_scans['managedbygid']
del check_scans['os']
del check_scans['description']
del check_scans['host_dn']
del check_scans['ip_cidr']
check_scans.to_csv('d:\\tmp\\' + yesterday + '_scanner.csv', sep =';', encoding = 'cp1252')
check_scans

###################################################################################################################
###################################################################################################################
grey_log_merged[grey_log_merged['category'].str.contains("dhcp")].drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
grey_log_merged[grey_log_merged['dst_info'].str.contains("\|sms\|")].drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
grey_log_merged[grey_log_merged['category'].str.contains("sw_distribution") & grey_log_merged['dst_info'].str.contains("server|sms|")].drop_duplicates(subset=['dst']).sort_values('connects', ascending = False)
sms_server=grey_log_merged[grey_log_merged['category'].str.contains("sw_distribution")]
sms_server=grey_log_merged[grey_log_merged['dst_info'].str.contains("server\|sms\|")]
#del (sms_server['change sysdb_x'])
#del (sms_server['change sysdb_y'])
grey_log_merged[grey_log_merged['dst'].str.contains("10\.141\.182\.31")]
grey_log_merged[(grey_log_merged['ports'].str.contains("tcp_9100,")) & (~grey_log_merged['dst_info'].str.contains('^print'))] #suche printer targets not signed as printer

#sysdb[sysdb['info'].str.contains("router")]#10.141.182.31

#log_analysis_dir_se
###################################################################################################################
#ip_unique_check.drop(['zzz','DNS','IP','Country',Location'],axis=1,inplace=True)
#display row with max value of column 'c' 
dfObj.loc[dfObj['c'].idxmax()]

https://wiki.siemens.com/pages/viewpage.action?pageId=96539918

#tufin secure track export copied from screen
#copy and paste into tracert .txt
#insert header:all_red_networks	ip	mask	comment
all_red_networks=pd.read_csv(r'D:\php\tracert.txt', sep='\t')
all_red_networks=pd.read_csv(r'D:\php\tracert.txt', sep='\t',dtype='str')


#sysdb tools ######################################################################################################
# Text in Spalte snic_comment aus Spalte info_extra löschen
#sysdb['info_extra'] = sysdb['info_extra'].replace(sysdb['snic_comment'],'')
import pandas as pd
import numpy as np
import ipaddress as iplib
from datetime import datetime, date, time, timezone, timedelta
import time
d = date.today()
today = d.isoformat()
today
y = date.today() - timedelta(1)
yesterday = y.isoformat()
yesterday

#today='2021-02-28'
#yesterday='2021-02-27'

sysdb = pd.read_csv(r'D:\php\sysdb_'+yesterday+'.gz',delimiter=';',encoding='utf-8',dtype='str')
#clean info extra from snic comment
#sysdb['info_extra']=sysdb[['snic_comment']].apply(lambda x: x.replace(x['snic_comment'],''),axis=1) #reduce a columns string with another columns string
sysdb['dns']=sysdb[['dns']].apply(lambda x: x['dns'].replace('|nan',''),axis=1)
#build info new
#sysdb['info_extra']=sysdb[['snic_comment']].apply(lambda x: x.replace(x['snic_comment'],''),axis=1)



import pandas as pd
import numpy as np
import ipaddress as iplib
from datetime import datetime, date, time, timezone, timedelta
import time
d = date.today()
today = d.isoformat()
today
y = date.today() - timedelta(1)
yesterday = y.isoformat()
yesterday

import time
sysdb = pd.read_csv(r'D:\php\sysdb_'+today+'.gz',delimiter=';',encoding='utf-8',dtype='str')
startTime = time.time()
sysdb['info'] = sysdb['sys_type'] + '|' + sysdb['dns'] + '|' + sysdb['corpflag'] + '|' + sysdb['info_extra'] + '|' + sysdb['snic_comment'] + '|' + sysdb['c'] + '|' + sysdb['l']
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))


sysdb[['info','info_extra','snic_comment']][990:1000]

import time
startTime = time.time()
#sysdb['info_extra'] = sysdb[['snic_comment']].apply(lambda x: x.replace(x['snic_comment'],''),axis=1)
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))

sysdb=sysdb.replace(np.NaN,'-')
#sysdb=sysdb.replace('|nan','')
startTime = time.time()
sysdb['info'] = sysdb['sys_type'] + '|' + sysdb['dns'] + '|' + sysdb['corpflag'] + '|' + sysdb['info_extra'] + '|' + sysdb['snic_comment'] + '|' + sysdb['c'] + '|' + sysdb['l']
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))


sysdb.to_csv(r'd:\php\sysdb_'+today+'.gz', sep = ';', index = False, encoding = 'utf-8')


#sysdb renew all info.

sysdb['info'] = sysdb['sys_type']
        + '|' + sysdb['dns'] 
        + '|' + sysdb['corpflag'] 
        + '|' + sysdb['info_extra'] 
        + '|' + sysdb['Comment'] 
        + '|' + sysdb['Country'] 
        + '|' + sysdb['Location'] 

#
################################################################# get red ips ###################################################
#################################################################################################################################
import pandas as pd
import numpy as np
import ipaddress as iplib
from datetime import datetime, date, time, timezone, timedelta
import time
d = date.today()
today = d.isoformat()
today
y = date.today() - timedelta(1)
yesterday = y.isoformat()
yesterday

dir = 'D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\'
path = dir + date_value + '.log_export_red.txt.src-dst.csv.unique.ips.csv.gz'
unique_ips = pd.read_csv(path, delimiter = ';', encoding='cp1252', dtype='str')
#unique_ips.drop_duplicates('IP')


###############################################################################################################################
#combine a csv list with sysdb
###############################################################################################################################
import pandas as pd
import numpy as np
dir = 'D:\\python\\'
path = dir + 'ip.txt'
ip_combi = pd.read_csv(path, delimiter = ';', encoding='cp1252', dtype='str')
ip_combi.replace(np.NaN,'-', inplace=True)
ip_combi.to_csv(path + '_x_sysdb.csv', sep = ';', encoding='cp1252')

################# check red connects total #####################

day='2021-01-29'
redlog_file = 'D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\' + day + '.log_export_red.txt.src-dst.csv.gz'
red_connects = pd.read_csv(redlog_file,sep=';',encoding='cp1252')
red_connects_sum = red_connects.connects.sum()
print(day+':::::::::::::::: ' + str(red_connects_sum))
rules = red_connects.groupby('rule_name',as_index=False).agg({'connects':'sum'})
rules = rules.sort_values('connects', ascending = False)
rules = rules.set_index('rule_name')
rules_connects_sum = rules.connects.sum()
print(day+':::::::::::::::: ' + str(rules_connects_sum))
grey_red2blue = rules.loc[['grey_red2blue']]
grey_red2blue

day='2020-12-30'
redlog_file = 'D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\' + day + '.log_export_red.txt.src-dst.csv.gz'
red_connects = pd.read_csv(redlog_file,sep=';',encoding='cp1252')
red_connects_sum = red_connects.connects.sum()
print(day+':::::::::::::::: ' + str(red_connects_sum))
rules = red_connects.groupby('rule_name',as_index=False).agg({'connects':'sum'})
rules = rules.sort_values('connects', ascending = False)
rules = rules.set_index('rule_name')
rules_connects_sum = rules.connects.sum()
print(day+':::::::::::::::: ' + str(rules_connects_sum))
grey_red2blue = rules.loc[['grey_red2blue']]
grey_red2blue




############################# statistic #####################################################################

import glob
import pandas as pd

logfiles=glob.glob(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021*.log_export_red.txt.src-dst.csv.gz')
print('date;rules_connects_sum;grey_red2blue_targets')
for log_file_name in logfiles:
    red_log_file  = pd.read_fwf(log_file_name, header=None)
    red_log_file = red_log_file[0].str.split(';', expand=True)
    red_log_file.drop(0)
    red_log_file["connects"] = red_log_file["connects"].apply(pd.to_numeric)
    red_log_file.rename(columns={3: 'connects', 9: 'rule_name'}, inplace = True)
    rules.sort_values('connects', ascending = False, inplace = True)
    rules_connects_sum = rules.connects.sum()
    date_string = log_file_name[56:66]
    rules = rules.set_index('rule_name')
    grey_red2blue_targets = rules.at['grey_red2blue','connects']
    ratio_in_percent = grey_red2blue_targets / rules_connects_sum * 1000
   #print (date_string)
    print(date_string + ';' + str(rules_connects_sum) + ';' + 'str(grey_red2blue_targets)' + ';' + 'str(ratio_in_percent)')

#
log_file_name = r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2020-12-01.log_export_red.txt.src-dst.csv.gz'
log_file_name = r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2020-08-01.log_export_red.txt.src-dst.csv.gz'
red_log_file = pd.read_csv(log_file_name, sep = ';', encoding = 'cp1252', usecols=[3,9])
rules = red_log_file.groupby('rule_name',as_index=False).agg({'connects':'sum'})
rules.sort_values('connects', ascending = False, inplace = True)
rules_connects_sum = rules.connects.sum()
date_string = log_file_name[56:66]
rules = rules.set_index('rule_name')
grey_red2blue_targets = rules.at['grey_red2blue','connects']
ratio_in_percent = grey_red2blue_targets / rules_connects_sum * 1000
outputstr = str(date_string + ';' + str(rules_connects_sum) + ';' + str(grey_red2blue_targets) + ';' + str(ratio_in_percent)).replace(".",",")
print(date_string + ';' + str(rules_connects_sum) + ';' + str(grey_red2blue_targets) + ';' + str(ratio_in_percent))

#tests
from io import StringIO
log_file_name = r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-01-01.log_export_red.txt.src-dst.csv.gz'
#log_file_name = r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2020-08-01.log_export_red.txt.src-dst.csv.gz'
red_log_file = pd.read_csv(StringIO(data), header=None, names=range(3))

red_log_file = pd.read_fwf(log_file_name, sep = ';', encoding = 'cp1252', header = None)
red_log_file = pd.read_fwf(log_file_name, sep = ';', encoding = 'cp1252', header = None)

#attach ; on header via sed
#zcat /mnt/d/compusafe/Kunden/pg/00_cofw/se_analysis/se_cofw_logs/2020-11-10.log_export_red.txt.src-dst.csv.gz | sed -e 's/;acceptance;orig/;acceptance;orig;/' | head -n 2 
log_file_name = r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2020-12-01.log_export_red.txt.src-dst.csv.gz'
#


log_file_name = r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-01-01.log_export_red.txt.src-dst.csv.gz'
red_log_file  = pd.read_fwf(log_file_name, header=None)
red_log_file = red_log_file[0].str.split(';', expand=True)
red_log_file
header = red_log_file.iloc[0].values
header
log_file_name = r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2020-08-01.log_export_red.txt.src-dst.csv.gz'
red_log_file  = pd.read_fwf(log_file_name, header=None)
red_log_file = red_log_file[0].str.split(';', expand=True)
red_log_file
header = red_log_file.iloc[0].values
header
red_log_file.rename(columns={0: 'src', 1: 'dst'}, inplace = True)
red_log_file.drop(0)
red_log_file


0: 'src', 1: 'dst', 2: 'direction': 'connects': 'tcp': 'udp': 'icmp','category': 'rule': 'rule_name': 'ports': 'accepted': 'acceptance': 




#################################################################################################################################
#  Grey Rule Reporting
#################################################################################################################################

import glob
import pandas as pd
logfiles=glob.glob(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2020-11-*.log_export_red.txt.src-dst.csv.gz')
print('date;rules_connects_sum;date;grey_red2blue_targets;date;ratio_in_percent;date;all_red_destination_ips;date;all_grey_destination_ips')
for log_file_name in logfiles:
    red_log_file = pd.read_csv(log_file_name, sep = ';', encoding = 'cp1252')#, usecols=[0,1,3,9])
    all_red_destination_ips = len(red_log_file.drop_duplicates(subset=['dst']))
    all_grey_destination_ips = len(red_log_file[red_log_file['rule_name']=='grey_red2blue'].drop_duplicates(subset=['dst']))
    rules = red_log_file.groupby('rule_name',as_index=False).agg({'connects':'sum'})
    rules.sort_values('connects', ascending = False, inplace = True)
    rules_connects_sum = rules.connects.sum()
    date_string = log_file_name[56:66]
    rules = rules.set_index('rule_name')
    grey_red2blue_targets = rules.at['grey_red2blue','connects']
    ratio_in_percent = grey_red2blue_targets / rules_connects_sum
    print(date_string + ';' + str(rules_connects_sum)                       + ';' + date_string + ';' + str(grey_red2blue_targets) + ';' + date_string + ';' + str(ratio_in_percent).replace('.',',') + ';' + date_string + ';' + str(all_red_destination_ips) + ';' + date_string + ';' + str(all_grey_destination_ips)) 

import glob
import pandas as pd
print('date;rules_connects_sum;date;grey_red2blue_targets;date;ratio_in_percent;date;all_red_destination_ips;date;all_grey_destination_ips')
logfiles = glob.glob(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2020-12-*.log_export_red.txt.src-dst.csv.gz')
print('date;rules_connects_sum;grey_red2blue_targets')
for log_file_name in logfiles:
    red_log_file = pd.read_csv(log_file_name, sep = ';', encoding = 'cp1252')#, usecols=[0,1,3,9])
    all_red_destination_ips = len(red_log_file.drop_duplicates(subset=['dst']))
    all_grey_destination_ips = len(red_log_file[red_log_file['rule_name']=='grey_red2blue'].drop_duplicates(subset=['dst']))
    rules = red_log_file.groupby('rule_name',as_index=False).agg({'connects':'sum'})
    rules.sort_values('connects', ascending = False, inplace = True)
    rules_connects_sum = rules.connects.sum()
    date_string = log_file_name[56:66]
    rules = rules.set_index('rule_name')
    grey_red2blue_targets = rules.at['grey_red2blue','connects']
    ratio_in_percent = grey_red2blue_targets / rules_connects_sum
    print(date_string + ';' + str(rules_connects_sum)                       + ';' + date_string + ';' + str(grey_red2blue_targets) + ';' + date_string + ';' + str(ratio_in_percent).replace('.',',') + ';' + date_string + ';' + str(all_red_destination_ips) + ';' + date_string + ';' + str(all_grey_destination_ips)) 

import glob
import pandas as pd
print('date;rules_connects_sum;date;grey_red2blue_targets;date;ratio_in_percent;date;all_red_destination_ips;date;all_grey_destination_ips')
logfiles=glob.glob(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-02-*.log_export_red.txt.src-dst.csv.gz')
print('date;rules_connects_sum;grey_red2blue_targets')
for log_file_name in logfiles:
    red_log_file = pd.read_csv(log_file_name, sep = ';', encoding = 'cp1252')#, usecols=[0,1,3,9])
    all_red_destination_ips = len(red_log_file.drop_duplicates(subset=['dst']))
    all_grey_destination_ips = len(red_log_file[red_log_file['rule_name']=='grey_red2blue'].drop_duplicates(subset=['dst']))
    rules = red_log_file.groupby('rule_name',as_index=False).agg({'connects':'sum'})
    rules.sort_values('connects', ascending = False, inplace = True)
    rules_connects_sum = rules.connects.sum()
    date_string = log_file_name[56:66]
    rules = rules.set_index('rule_name')
    grey_red2blue_targets = rules.at['grey_red2blue','connects']
    ratio_in_percent = grey_red2blue_targets / rules_connects_sum
    print(date_string + ';' + str(rules_connects_sum)                       + ';' + date_string + ';' + str(grey_red2blue_targets) + ';' + date_string + ';' + str(ratio_in_percent).replace('.',',') + ';' + date_string + ';' + str(all_red_destination_ips) + ';' + date_string + ';' + str(all_grey_destination_ips)) 



logfiles=glob.glob(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-03-*.log_export_red.txt.src-dst.csv.gz')
print('date;rules_connects_sum;grey_red2blue_targets')
for log_file_name in logfiles:
    red_log_file = pd.read_csv(log_file_name, sep = ';', encoding = 'cp1252')#, usecols=[0,1,3,9])
    all_red_destination_ips = len(red_log_file.drop_duplicates(subset=['dst']))
    all_grey_destination_ips = len(red_log_file[red_log_file['rule_name']=='grey_red2blue'].drop_duplicates(subset=['dst']))
    rules = red_log_file.groupby('rule_name',as_index=False).agg({'connects':'sum'})
    rules.sort_values('connects', ascending = False, inplace = True)
    rules_connects_sum = rules.connects.sum()
    date_string = log_file_name[56:66]
    rules = rules.set_index('rule_name')
    grey_red2blue_targets = rules.at['grey_red2blue','connects']
    ratio_in_percent = grey_red2blue_targets / rules_connects_sum
    print(date_string + ';' + str(rules_connects_sum)                       + ';' + date_string + ';' + str(grey_red2blue_targets) + ';' + date_string + ';' + str(ratio_in_percent).replace('.',',') + ';' + date_string + ';' + str(all_red_destination_ips) + ';' + date_string + ';' + str(all_grey_destination_ips)) 

##########################################################################################
#report past 7 days start
##########################################################################################
import glob
import pandas as pd
from datetime import datetime, date, time, timezone, timedelta
import time

print('Week Day;Date;cw;All red to blue connections;cw;All Grey Rule Connections;cw;Rational[%]: Grey Rule Connections / All red to blue Connections;cw;All blue destination IPs used;cw;All blue destination IPs used via Grey Rule;cw;Destination IPs used via White Rules;cw;Rational[%]: Destination IPs used via White Rules / All blue destination IPs used;cw;Rational[%]: Destination IPs used via Grey Rule / All blue destination IPs used')

step = 1
i = 7
while i > 0:
    d = date.today() - timedelta(i) 
    day_str=d.isoformat()
    log_file_name = 'D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\' + day_str + '.log_export_red.txt.src-dst.csv.gz'
    red_log_file = pd.read_csv(log_file_name, sep = ';', encoding = 'cp1252')#, usecols=[0,1,3,9]
    all_blue_destination_ips = len(red_log_file.drop_duplicates(subset=['dst']))
    all_grey_destination_ips = len(red_log_file[red_log_file['rule_name']=='grey_red2blue'].drop_duplicates(subset=['dst']))
    rules = red_log_file.groupby('rule_name',as_index=False).agg({'connects':'sum'})
    rules.sort_values('connects', ascending = False, inplace = True)
    rules_connects_sum = rules.connects.sum()
    date_string = log_file_name[56:66]
    rules = rules.set_index('rule_name')
    grey_red2blue_targets = rules.at['grey_red2blue','connects']
    ratio_in_percent = grey_red2blue_targets / rules_connects_sum
    print(';' + date_string + ';;' + str(rules_connects_sum) + ';;' + str(grey_red2blue_targets) + ';;' + str(ratio_in_percent).replace('.',',') + ';;' + str(all_blue_destination_ips) + ';;' + str(all_grey_destination_ips)) 
    i = i - step

##########################################################################################
#report past 7 days finale 
##########################################################################################

##########################################################################################
#report past 7 days Top 10 Grey Rule Blue Destinations
##########################################################################################
import glob
import pandas as pd
import numpy as np
from datetime import datetime, date, time, timezone, timedelta
import time

def get_latest_sysdb():
     files=glob.glob(r'D:\php\sysdb*.gz')
     print('load latest sysdb file: ' + files[-1])
     sysdb = pd.read_csv(files[-1],sep = ';',encoding = "utf-8", dtype = 'str')
     return sysdb
#

#print('date;rules_connects_sum;date;grey_red2blue_targets;date;ratio_in_percent;date;all_red_destination_ips;date;all_grey_destination_ips')
if not 'sysdb' in dir():
    sysdb = get_latest_sysdb()

step = 1
start_day = 7 #before real date today
end_day = start_day - 7 #before real date today

i = start_day
while i > end_day:
    d = date.today() - timedelta(i)
    day_str = d.isoformat()
    log_file_name = 'D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\' + day_str + '.log_export_red.txt.src-dst.csv.gz'
    log = pd.read_csv(log_file_name, sep = ';', encoding = 'cp1252')
    log = log[log['rule_name']=='grey_red2blue']
    if i == start_day:
        week_log = log
    else:
        week_log = pd.concat([week_log,log],ignore_index=True)
    print (day_str,': ', week_log.shape)
    i = i - step

week_log.sort_values('connects', ascending = False, inplace = True)
week_log_reduced = week_log[['dst','connects']]
dst_list = week_log_reduced.groupby('dst')
dst_list_agg = dst_list.aggregate({'connects': np.sum})
dst_list_agg.sort_values('connects', ascending = False, inplace = True)

dst_list_agg = dst_list_agg/7
dst_list_agg['connects'] = dst_list_agg['connects'].astype('int64')
dst_list_agg_index = dst_list_agg.reset_index()
dst_list_all = pd.merge(left=dst_list_agg_index, right=sysdb, how='left', left_on='dst', right_on='ip')
dst_top_10 = dst_list_all.head(11)

dst_top_10.to_csv('D:\\compusafe\\Kunden\\pg\\00_cofw\\performance_logs\\grey_rule_weekly_top10_dst_'+today+'.csv', sep = ';', encoding = 'cp1252')

#### do some analysis
#sysdb_reduced = sysdb[['ip','c','l','info']]
week_log.replace(np.NaN,'-', inplace=True)
week_log_x = pd.merge(left=week_log, right=sysdb[['ip','c','l','info','ip_cidr']], how='left', left_on='src', right_on='ip')
week_log_x = pd.merge(left=week_log_x, right=sysdb[['ip','c','l','info','ip_cidr']], how='left', left_on='dst', right_on='ip')
week_log_x = week_log_x.rename(columns={'c_x': 'src_c', 'l_x': 'src_l', 'info_x': 'src_info','c_y': 'dst_c', 'l_y': 'dst_l', 'info_y': 'dst_info'})
week_log_x = week_log_x[["src", "src_c", "src_l", "src_info","dst", "dst_c", "dst_l", "dst_info", "connects", "ports" ]]

#week_log_x[week_log_x['dst'] == '139.25.78.165']#.to_clipboard()

ssh_traffic = week_log_x[week_log_x['ports'].str.contains("tcp_22,")]
ssh_traffic
ssh_traffic.to_csv('D:\\compusafe\\Kunden\\pg\\00_cofw\\performance_logs\\grey_rule_weekly_ssh_'+ today +'.csv', sep = ';', encoding = 'cp1252')
rdp_traffic = week_log_x[week_log_x['ports'].str.contains("(tc|ud)p_3389,")]
rdp_traffic
rdp_traffic.to_csv('D:\\compusafe\\Kunden\\pg\\00_cofw\\performance_logs\\grey_rule_weekly_rdp_'+ today +'.csv', sep = ';', encoding = 'cp1252')
vnc_traffic = week_log_x[week_log_x['ports'].str.contains("tcp_5[8-9]0[0-9],")]
vnc_traffic
vnc_traffic.to_csv('D:\\compusafe\\Kunden\\pg\\00_cofw\\performance_logs\\grey_rule_weekly_vnc_'+ today +'.csv', sep = ';', encoding = 'cp1252')

ssh_traffic['flag'] = ssh_traffic.apply(lambda x: 'ssh#' + str(x['src']) + '#' + str(x['dst']),axis=1)
rdp_traffic['flag'] = rdp_traffic.apply(lambda x: 'rdp#' + str(x['src']) + '#' + str(x['dst']),axis=1)
vnc_traffic['flag'] = vnc_traffic.apply(lambda x: 'vnc#' + str(x['src']) + '#' + str(x['dst']),axis=1)

protocols_critical = pd.concat([ssh_traffic,rdp_traffic,vnc_traffic])
protocols_critical_group = protocols_critical.groupby('flag')

protocols_critical_group_agg = protocols_critical_group.aggregate({'connects': np.sum})

protocols_critical_group_agg.sort_values('connects', ascending = False, inplace = True)

protocols_critical_group_agg_index = protocols_critical_group_agg.reset_index()

protocols_critical_group_agg_index['protocol'] = protocols_critical_group_agg_index.apply(lambda x: x['flag'].split('#')[0], axis = 1)
protocols_critical_group_agg_index['src'] = protocols_critical_group_agg_index.apply(lambda x: x['flag'].split('#')[1], axis = 1)
protocols_critical_group_agg_index['dst'] = protocols_critical_group_agg_index.apply(lambda x: x['flag'].split('#')[2], axis = 1)
protocols_critical_result = protocols_critical_group_agg_index[['flag','protocol','connects','src','dst']]

protocols_critical_result_x = pd.merge(left=protocols_critical_result, right=sysdb[['ip','c','l','info','ip_cidr']], how='left', left_on='src', right_on='ip')
protocols_critical_result_x = pd.merge(left=protocols_critical_result_x, right=sysdb[['ip','c','l','info','ip_cidr']], how='left', left_on='dst', right_on='ip')

protocols_critical_result_x.rename(columns={'c_x': 'src_c', 'l_x': 'src_l', 'info_x': 'src_info','c_y': 'dst_c', 'l_y': 'dst_l', 'info_y': 'dst_info'}, inplace = True)
protocols_critical_result_x = protocols_critical_result_x[['flag','src', 'src_c', 'src_l', 'src_info','dst', 'dst_c', 'dst_l', 'dst_info', 'connects']]
protocols_critical_result_x.drop_duplicates(subset='flag',inplace = True)
protocols_critical_result_x.to_csv('D:\\compusafe\\Kunden\\pg\\00_cofw\\performance_logs\\critical_protocols_list_'+today+'.csv', sep = ';', encoding = 'cp1252')

#weekly mail_relay_traffic
mailrelay_traffic = week_log_x[week_log_x['ports'].str.contains("tcp_25,")]
mailrelay_traffic_list = mailrelay_traffic.groupby('dst')
mailrelay_traffic_list_agg = mailrelay_traffic_list.aggregate({'connects': np.sum})
mailrelay_traffic_list_agg.sort_values('connects', ascending = False, inplace = True)
#sysdb_reduced = sysdb[['ip','dns','c','l','info']]
mailrelay_traffic_list_x = pd.merge(left = mailrelay_traffic_list_agg, right=sysdb[['ip','c','l','info','ip_cidr']], how='left', left_on='dst', right_on='ip')
mailrelay_traffic_list_x.to_csv('D:\\tmp\\mailrelay_servers_weekly_' + yesterday + '.csv', sep = ';', encoding = 'cp1252')

#weekly dhcp traffic
dhcp_traffic = week_log_x[week_log_x['ports'].str.contains("udp_67,")]
dhcp_traffic_list = dhcp_traffic.groupby('dst')
dhcp_traffic_list_agg = dhcp_traffic_list.aggregate({'connects': np.sum})
dhcp_traffic_list_agg.sort_values('connects', ascending = False, inplace = True)
#sysdb_reduced = sysdb[['ip','dns','c','l','info']]
dhcp_traffic_list_x = pd.merge(left = dhcp_traffic_list_agg, right=sysdb[['ip','c','l','info','ip_cidr']], how='left', left_on='dst', right_on='ip')
dhcp_traffic_list_x.to_csv('D:\\tmp\\dhcp_servers_weekly_' + yesterday + '.csv', sep = ';', encoding = 'cp1252')

#weekly printers unknown traffic
printers_unknown = week_log_x[week_log_x['ports'].str.contains("tcp_9100,")]
printers_unknown_list = printers_unknown.groupby('dst')
printers_unknown_list_agg = printers_unknown_list.aggregate({'connects': np.sum})
printers_unknown_list_agg.sort_values('connects', ascending = False, inplace = True)
#sysdb_reduced = sysdb[['ip','dns','c','l','info']]
printers_unknown_list_x = pd.merge(left = printers_unknown_list_agg, right=sysdb[['ip','c','l','info','ip_cidr']], how='left', left_on='dst', right_on='ip')
printers_unknown_list_x.to_csv('D:\\tmp\\printers_unknown_weekly_' + yesterday + '.csv', sep = ';', encoding = 'cp1252')

#weekly Energy servers
#energy_server = week_log_x[week_log_x['info'].str.contains("(E|e)nergy") OR week_log_x['info'].str.contains("(PG|pg).")]
energy_server = week_log_x[week_log_x['dst_info'].str.contains("(E|e)nergy")]
energy_server_list = energy_server.groupby('dst')
energy_server_list_agg = energy_server_list.aggregate({'connects': np.sum})
energy_server_list_agg.sort_values('connects', ascending = False, inplace = True)
#sysdb_reduced = sysdb[['ip','dns','c','l','info']]
energy_server_list_x = pd.merge(left = energy_server_list_agg, right=sysdb[['ip','c','l','info','ip_cidr']], how='left', left_on='dst', right_on='ip')
energy_server_list_x.to_csv('D:\\tmp\\energy_server_weekly_' + yesterday + '.csv', sep = ';', encoding = 'cp1252')


##########################################################################################
#report past 7 days Top 10 Grey Rule Blue Destinations finale
##########################################################################################



#
#tests
red_log_file = pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-02-01.log_export_red.txt.src-dst.csv.gz', sep = ';', encoding = 'cp1252')#, usecols=[0,1,3,9])
all_red_destination_ips = len(red_log_file.drop_duplicates(subset=['dst']))
all_grey_destination_ips = len(red_log_file[red_log_file['rule_name']=='grey_red2blue'].drop_duplicates(subset=['dst']))
rules = red_log_file.groupby('rule_name',as_index=False).agg({'connects':'sum'})
rules.sort_values('connects', ascending = False, inplace = True)
rules_connects_sum = rules.connects.sum()
date_string = log_file_name[56:66]
rules = rules.set_index('rule_name')
grey_red2blue_targets = rules.at['grey_red2blue','connects']
ratio_in_percent = grey_red2blue_targets / rules_connects_sum
print(date_string + ';' + str(rules_connects_sum)                       + ';' + date_string + ';' + str(grey_red2blue_targets) + ';' + date_string + ';' + str(ratio_in_percent).replace('.',',') + ';' + date_string + ';' + str(all_red_destination_ips) + ';' + date_string + ';' + str(all_grey_destination_ips)) 



#https://stackoverflow.com/questions/39880627/in-pandas-how-to-delete-rows-from-a-data-frame-based-on-another-data-frame


#################### Merlin Procedures ###########################
#################### Merlin Procedures ###########################

#Merlin MIG Overall Status
# + Batch assigned
# + Cancelled
# - Done
# - In Hypercare
# + In preparation
# + Not scheduled
# + On Hold
# + Postponed
# - Ready for migration
# - User cutover in progress

import pandas as pd
import numpy as np
import re

merlin = pd.read_excel(r"D:\tmp\survey_lml_pmo.xlsx", sheet_name = 'Export',dtype = 'str') 
merlin.replace(np.NaN,"",inplace = True)
#radar = pd.read_csv(r"D:\tmp\control_migration_radar.csv")
radar = pd.read_excel(r"D:\tmp\control_migration_radar.xlsx", sheet_name = 'Export',dtype = 'str') 

#merlin[merlin['SAL']=='BUD K']['MIG Overall Status']
#merlin[merlin['SAL']=='OSL']['MIG Overall Status']
#merlin[merlin['SAL']=='NBG K']['conf. MIG Date Local']

merlin_mono = merlin[merlin['Type'].str.contains('Type (A|B)', case = False)]
merlin_relevant = merlin[merlin['Type'].str.contains('Type (A|B|C|D|E)', case = False)]

mono_ip_ranges = pd.merge(left = merlin_mono, right=snic, how='left', left_on='SAL', right_on='Location')
mono_ip_ranges_blue = mono_ip_ranges[~mono_ip_ranges['MIG Overall Status'].str.contains('(Done|Hypercare|Ready|cutover)')]
mono_ip_ranges_blue = mono_ip_ranges_blue[mono_ip_ranges_blue['VPN name']=="Siemens VPN"]
mono_ip_ranges_blue.replace(np.NaN,"",inplace = True)
mono_ip_ranges_blue_not_voice = mono_ip_ranges_blue[~mono_ip_ranges_blue['Comment'].str.contains("Voi",case = False )]
mono_ip_ranges_blue_not_voice.to_clipboard()

hc_status = merlin.groupby('MIG Overall Status',as_index=False).agg({'SE HC':'sum'})
hc_status
hc_total = hc_status.sum()
hc_total
se_locations_type_in_scope = merlin.loc[merlin['initial location scope'] == 'in scope'].loc[merlin['Type'].isin(['Type A', 'Type B', 'Type C', 'Type D', 'Type D,Type E', 'Type E', 'Type NEW'])].replace(np.NaN,"")
se_locations_type_in_scope
locations_migrated_hc = se_locations_type_in_scope.loc[se_locations_type_in_scope['MIG Overall Status'].isin(['Done', 'In Hypercare', 'User cutover in progress'])].replace(np.NaN,"").sum('SE HC')
#Available Types: 'Type A', 'Type B', 'Type C', 'Type D', 'Type D,Type E', 'Type E', 'Type G', 'Type H', 'Type NEW'
#types = np.array([['Type A'], ['Type B'], ['Type C'], ['Type D'], ['Type D,Type E'],['Type E'], ['Type new']])
#types = pd.DataFrame(types)
                       

#merlin = merlin.loc[merlin['Type'].isin(['Type A', 'Type B', 'Type C', 'Type D', 'Type E', 'Type new'])]
se_locations.to_csv(r"D:\tmp\se_locations_preversion.txt",index = False, header=False, encoding = 'cp1252')#delete boxes and home
#COFW analysis "se_locations.txt"
#"D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\se_locations.txt"
merlin.groupby('MIG Overall Status',as_index=False).agg({'SE HC':'sum'})
          MIG Overall Status    SE HC
0             Batch assigned  22707.0
1                  Cancelled    189.0
2                       Done  24823.0
3               In Hypercare   5259.0
4             In preparation  22891.0
5              Not scheduled   5209.0
6                    On Hold     96.0
7                  Postponed   3105.0
8        Ready for migration   2202.0
9   User cutover in progress    542.0
10             not scheduled   3453.0



########################### crt oracle ############################################################################
########################### crt oracle ############################################################################
########################### crt oracle ############################################################################

import pd
import cx_Oracle
cx_Oracle.init_oracle_client(lib_dir=r"C:\oracle12\ora121_x64\base\client\lib")
ip = '10.141.183.146'
port = 1521
SID = 'arkdpdb.db2.ashvcn.oraclevcn.com'
dsn_tns = cx_Oracle.makedsn(ip, port, SID)

connection = cx_Oracle.connect('EFUSER_NC_RO', 'uKG1m6Q_ogg_GDsO7uY7', dsn_tns)

query = """SELECT* 
           FROM TRANSACTION
           WHERE DIA_DAT >=to_date('15.02.28 00:00:00',  'YY.MM.DD HH24:MI:SS')
           AND (locations <> 'PUERTO RICO'
           OR locations <> 'JAPAN')
           AND CITY='LONDON'"""
df_ora = pd.read_sql(query, con=connection)



devqa.ora.siemens-energy.com
 10.141.183.146 OR 10.141.183.147 OR 10.141.183.157

import cx_Oracle
import os
import sys

print(sys.version)
#print(os.environ['ORACLE_HOME'])
print(os.environ['path'])

con = cx_Oracle.connect('EFUSER_NC_RO/uKG1m6Q_ogg_GDsO7uY7@devqa.ora.siemens-energy.com:1512')

User                      EFUSER_NC_RO
PW                         uKG1m6Q_ogg_GDsO7uY7
Connection:
  (DESCRIPTION =
    (ADDRESS_LIST=
      (ADDRESS = (PROTOCOL = TCP)(HOST = devqa.ora.siemens-energy.com)(PORT = 1521)))
    (CONNECT_DATA =
      (SERVER = DEDICATED)
      (SERVICE_NAME = arkdpdb.db2.ashvcn.oraclevcn.com)
    )
  )
DatabaseView V_SER_APP_INTERFACE     


################## ad101 systems #########################################################################################
# get all AD101 computers: d:\php\AdFind.exe -b DC=ad101,DC=siemens-energy,DC=net -csv -csvdelim ; -f "objectcategory=computer" dNSHostName managedBy operatingSystem description sAMAccountType userAccountControl primaryGroupID > d:\php\ad101_all_computers_2021-02-08.csv
################## ad101 systems #########################################################################################

import pandas as pd
ad101_computers = pd.read_csv(r'\\139.23.160.99\d$\php\ad101_all_computers.csv', sep =';', encoding = 'cp1252')
ad101_computers
import numpy as np
ad101_computers.replace(np.NaN,'-', inplace=True)

ad101_server = ad101_computers[ad101_computers['operatingSystem'].str.contains("Server")]
ad101_server.to_csv(r'd:\tmp\ad101_server.csv', sep =';', encoding = 'cp1252')



################################################## 1. check traffic from energy to express #####################
import pandas as pd
from my_functions import *
import re
from datetime import datetime, date, time, timezone, timedelta
import time
import numpy as np


d = date.today()
today = d.isoformat()
today
y = date.today() - timedelta(1)
yesterday = y.isoformat()
yesterday


day_str = '2021-09-30'
energy = pd.read_csv('D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\' + day_str +  '.log_export_red.txt.src-dst.csv.gz', sep = ';', dtype='str')
energy = energy[['src','dst','direction','connects','category','rule_name','ports','orig']]
energy['pair'] = energy['src'] + ';' + energy['dst']

express = pd.read_csv('D:\\compusafe\\Kunden\\mobility\\00_firewall_cofw\\analysis\\' + day_str +  '.log_export_blue.txt.src-dst.csv.gz', sep = ';', dtype='str')
express = express[['src','dst','direction','connects','category','rule_name','ports','orig']]
express['pair'] = express['src']+';'+express['dst']
energy2express = pd.merge(left=energy, right=express, how = 'inner', on = 'pair')
del energy2express['src_x']
del energy2express['dst_x']
del energy2express['direction_x']
del energy2express['connects_x']
del energy2express['category_x']
del energy2express['rule_name_x']
del energy2express['ports_x']
del energy2express['orig_x']
del energy2express['pair']
energy2express.rename(columns={"src_y": "src", "dst_y": "dst", "direction_y": "direction", "connects_y": "connects", "category_y": "category", "rule_name_y": "rule_name", "ports_y": "ports", "orig_y": "orig"}, inplace = True)

if not 'sysdb' in dir():
    sysdb = get_latest_sysdb()

sysdbpart = sysdb[['ip','info']]
energy2express_merged = pd.merge(left=energy2express, right=sysdbpart, how='left', left_on='src', right_on='ip')
del energy2express_merged['ip']
energy2express_merged.rename(columns={"info": "src_info"}, inplace = True)
energy2express_merged = pd.merge(left=energy2express_merged, right=sysdbpart, how='left', left_on='dst', right_on='ip')
del energy2express_merged['ip']
energy2express_merged.rename(columns={"info": "dst_info"}, inplace = True)
energy2express_merged.replace(to_replace = 'NaN', value = '', inplace = True)
energy2express_merged.replace(np.NaN,"-")

startTime = time.time()
energy2express_merged['category'] = energy2express_merged[['src','src_info','dst','dst_info','ports']].apply(lambda x: autoanalysis(str(x['src']),str(x['src_info']),str(x['dst']),str(x['dst_info']),str(x['ports'])),axis=1)
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))

energy2express_merged = energy2express_merged[['src', 'src_info', 'dst', 'dst_info', 'ports', 'category', 'connects']].sort_values('connects', ascending = False)#.to_clipboard(sep = '\t', index = None)
energy2express_merged[['connects','category','ports','src_info','dst_info']].sort_values('connects', ascending = False)#.to_clipboard(sep = '\t', index = None)
energy2express_merged.replace('|scan', '', inplace = True)

#energy2express_merged.to_csv('d:\\tmp\\energy2express_' + day_str +  '.csv', sep = ';', index = None, encoding = 'cp1252')
energy2express_merged.replace(np.NaN,"-", inplace = True)
energy2express_merged[energy2express_merged['category'] == 'storage']
energy2express_merged[energy2express_merged['category'] == '#_scan']
energy2express_merged[energy2express_merged['ports'].str.contains('tcp_7680,')]
energy2express_merged = energy2express_merged[~energy2express_merged['ports'].str.contains('tcp_7680,')]
energy2express_merged[energy2express_merged['dst_info'].str.contains('^dc')]
energy2express_merged = energy2express_merged[~energy2express_merged['dst_info'].str.contains('^dc')]
energy2express_merged = energy2express_merged[~energy2express_merged['src_info'].str.contains('^dc')]
energy2express_merged = energy2express_merged[~energy2express_merged['category'].str.contains('#_scan')]
energy2express_merged = energy2express_merged[~energy2express_merged['src'].str.contains('^139\.24\.159\.241$')] #139.24.159.241 WUH I Scanner
#energy2express_merged.to_csv('d:\\tmp\\energy2express_' + day_str +  '.csv', sep = ';', index = None, encoding = 'cp1252')
energy2express_merged.to_excel('d:\\tmp\\energy2express_' + day_str +  '.xlsx', index = None, sheet_name='energy2express')


################################################## 2. check traffic from express to energy #####################
import pandas as pd
from my_functions import *
import re
from datetime import datetime, date, time, timezone, timedelta
import time
import numpy as np

d = date.today()
today = d.isoformat()
today
y = date.today() - timedelta(1)
yesterday = y.isoformat()
yesterday


#day_str = yesterday #'2021-02-26' # 
day_str = '2021-09-30'
#sysdb = pd.read_csv('D:\\php\\sysdb_' + yesterday + '.gz',delimiter=';',encoding='utf-8',dtype='str')
#sysdb = pd.read_csv('D:\\php\\sysdb_' + today + '.gz',delimiter=';',encoding='utf-8',dtype='str')

express = pd.read_csv('D:\\compusafe\\Kunden\\mobility\\00_firewall_cofw\\analysis\\' + day_str + '.log_export_red.txt.src-dst.csv.gz', sep = ';', dtype='str')
express = express[['src','dst','direction','connects','category','rule_name','ports','orig']]
express['pair']=express['src']+';'+express['dst']

energy = pd.read_csv('D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\' + day_str +'.log_export_blue.txt.src-dst.csv.gz', sep = ';', dtype='str')
energy = energy[['src','dst','direction','connects','category','rule_name','ports','orig']]
energy['pair']=energy['src']+';'+energy['dst']

express2energy = pd.merge(left = express, right = energy, how = 'inner', on='pair')

del express2energy['src_x']
del express2energy['dst_x']
del express2energy['direction_x']
del express2energy['connects_x']
del express2energy['category_x']
del express2energy['rule_name_x']
del express2energy['ports_x']
del express2energy['orig_x']
del express2energy['pair']
express2energy.rename(columns={"src_y": "src", "dst_y": "dst", "direction_y": "direction", "connects_y": "connects", "category_y": "category", "rule_name_y": "rule_name", "ports_y": "ports", "orig_y": "orig"}, inplace = True)
sysdbpart = sysdb[['ip','info']]
#express2energy_merged = pd.merge(left=express2energy, right=sysdbpart, how='left', left_on='src', right_on='ip')
express2energy_merged = pd.merge(left=express2energy, right=sysdb[['ip','c','l','info']], how='left', left_on='src', right_on='ip')
del express2energy_merged['ip']
#express2energy_merged.rename(columns={"info": "src_info"}, inplace = True)
express2energy_merged.rename(columns={"c": "src_c","l": "src_l","info": "src_info"}, inplace = True)
express2energy_merged = pd.merge(left=express2energy_merged, right = sysdb[['ip','c','l','info']], how='left', left_on='dst', right_on='ip')
######### Fortsetzung #############################
######### Fortsetzung #############################
######### Fortsetzung #############################
######### Fortsetzung #############################
######### Fortsetzung #############################
del express2energy_merged['ip']
express2energy_merged.rename(columns={"c": "dst_c","l": "dst_l","info": "dst_info"}, inplace = True)
#express2energy_merged = express2energy_merged.convert_dtypes()
express2energy_merged.replace(to_replace = 'NaN', value = '', inplace = True)
express2energy_merged.replace(np.NaN,"-",inplace=True)
#express2energy_merged['category'] = str('')

startTime = time.time()
express2energy_merged['category'] = express2energy_merged[['src','src_info','dst','dst_info','ports']].apply(lambda x: autoanalysis(str(x['src']),str(x['src_info']),str(x['dst']),str(x['dst_info']),str(x['ports'])),axis=1)
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))
express2energy_merged = express2energy_merged[['src', 'src_info', 'dst', 'dst_info', 'ports', 'category', 'connects']].sort_values('connects', ascending = False)#.to_clipboard(sep = '\t', index = None)
express2energy_merged.replace('|scan', '', inplace = True)

express2energy_merged.replace(np.NaN,"-", inplace = True)
express2energy_merged[express2energy_merged['category'] == 'storage']
express2energy_merged[express2energy_merged['category'] == '#_scan']
express2energy_merged[express2energy_merged['ports'].str.contains('tcp_7680,')]
express2energy_merged = express2energy_merged[~express2energy_merged['ports'].str.contains('tcp_7680,')]
express2energy_merged[express2energy_merged['dst_info'].str.contains('^dc')]
express2energy_merged = express2energy_merged[~express2energy_merged['dst_info'].str.contains('^dc')]
express2energy_merged = express2energy_merged[~express2energy_merged['src_info'].str.contains('^dc')]
express2energy_merged = express2energy_merged[~express2energy_merged['category'].str.contains('#_scan')]
express2energy_merged = express2energy_merged[~express2energy_merged['ports'].str.contains('^icmp,$')]

#express2energy_merged.to_csv('d:\\tmp\\express2energy_' + day_str + '.csv', sep = ';', index = None, encoding = 'cp1252')
express2energy_merged.to_excel('d:\\tmp\\express2energy_' + day_str +  '.xlsx', index = None, sheet_name='express2energy')

################ rote aktive IP Ranges finden #############################################
day_str='2021-02-12'
energy = pd.read_csv('D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\' + day_str + '.log_export_red.txt.src-dst.csv.gz', sep = ';', dtype='str')
#pd.merge(left = energy_red_ips , right = sys_part, how='left', left_on='src', right_on='ip')[['ip_cidr','c','l','connects']]
red_ip_ranges_cidr_se = pd.merge(left = energy_red_ips , right = sys_part, how='left', left_on='src', right_on='ip')[['ip_cidr','c','l']].drop_duplicates(subset=['ip_cidr'])
red_ip_ranges_cidr_se.to_clipboard(index = None)


##### SNIC-DB #############################################################################
snic = pd.read_csv('d:\\snic\\20210214-snic_ip_network_assignments.csv',delimiter=';', encoding='latin_1',engine='python' ).fillna('') 
snic.fillna('', inplace = True) 
snic[snic['Comment'].str.lower().contains('ai4sis')]#.to_clipboard(sep = '\t', index = None)
snic[snic['IP-net-base'].str.contains('^157\.163\.')]#.to_clipboard(sep = '\t', index = None)
snic[snic['Comment'].str.lower().str.contains('ai4sis')]#.to_clipboard(sep = '\t', index = None)
snic[snic['Comment'].str.lower().str.contains('saacon')]#.to_clipboard(sep = '\t', index = None)

#hole aktuelle info aus sysdb #############################################################
#hole aktuelle info aus sysdb #############################################################
#hole aktuelle info aus sysdb #############################################################

#sysdb = pd.read_csv(r'D:\php\sysdb_'+today+'.gz',delimiter=';',encoding='utf-8',dtype='str')
#ipl = pd.read_clipboard()
ipl = pd.merge(left = ipl, right=sysdb, how='left', left_on='ip', right_on='ip')
#ipl.to_clipboard(index = None)
## ipl <-> snic abgleich ######
ipl['ip_cidr'] = ipl.apply(lambda x: get_ip_range(x['ip']) , axis=1)
ipl = pd.merge(left=ipl, right=snic, left_on='ip_cidr', right_on='IP range/CIDR')
del ipl['ip_base_bin']
del ipl['ip_top_bin']


#ipl.drop_duplicates(subset=['ip']).to_clipboard(index=None,header=None)
#ipl.drop_duplicates(subset=['ip'])['ip','info'].to_clipboard(index=None,header=None)
#ipl.to_clipboard(sep = '\t', index = None, header = None)
ruleset = pd.merge(left = ipl, right=sysdb, how='left', left_on='ip', right_on='ip')
ruleset
ruleset.to_clipboard(sep = '\t', index = None, header = None)
#ruleset[['dns','ip','info']].to_clipboard(sep = '\t', index = None, header = None)
#pip install openpyxl
from openpyxl import load_workbook
ipl = pd.read_excel(r'D:\python\sysdb_maintain.xlsm', sep = ';', sheet_name = 'get_info_for_ip', encoding = 'cp1252', dtype = 'str')
ipl = pd.merge(left = ipl, right=sysdb, how='left', left_on='ip', right_on='ip')
ipl.to_clipboard(sep = '\t', index = None)
#ipl.to_excel(r'D:\python\sysdb_maintain.xlsm', sheet_name = 'get_info_for_ip', encoding = 'cp1252')

############## get-host-info ############################################################
import subprocess
import pandas as pd
import os
from pandas.io import clipboard
hostname = 'cnsha08060'
cmd = 'd:\powershell\get-host-info-py.ps1 -hostname ' + hostname
completed = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
completed.stdout
host_info = pd.read_csv(r'd:\powershell\0.csv',sep = ';')
host_info.to_clipboard(index = None, header = None)

completed.stdout#.to_clipboard(index = None, header = None)
#addToClipBoard(completed.stdout)
#print("stderr:", completed.stderr)
clipboard.copy(completed.stdout)

tcp_135,tcp_445,tcp_3389,tcp_5666,

############### Log Analysis SPPAL oder SL #############################################
############### Log Analysis SPPAL oder SL #############################################
############### Log Analysis SPPAL oder SL #############################################
#D:\compusafe\Kunden\IC_MOL_LAS_Goliath_David\Firewall\analysis\firewall_logs\2021-03-02.log_export.txt.src-dst.csv.gz
import pandas as pd
import numpy as np
from my_functions import *

day_str = '2021-03-02'
yesterday = day_str
sl_log = pd.read_csv('D:\\compusafe\\Kunden\\IC_MOL_LAS_Goliath_David\\Firewall\\analysis\\firewall_logs\\' + day_str + '.log_export.txt.src-dst.csv.gz',sep = ';', encoding = 'cp1252', dtype = 'str')
#sysdb = pd.read_csv(r'd:\php\sysdb_' + yesterday + '.gz', sep = ';', encoding = 'utf-8', dtype = 'str')
#sysdb = pd.read_csv(r'd:\php\sysdb_' + today     + '.gz', sep = ';', encoding = 'utf-8', dtype = 'str')
sysdbpart = sysdb[['ip','c','l','info']]
sl_log = pd.merge(left=sl_log, right=sysdbpart, how='left', left_on='src', right_on='ip')
sl_log.rename(columns={"c": "src_c", "l": "src_l", "info": "src_info"}, inplace = True)
del sl_log['ip']
sl_log = pd.merge(left=sl_log, right=sysdbpart, how='left', left_on='dst', right_on='ip')
sl_log.rename(columns={"c": "dst_c", "l": "dst_l", "info": "dst_info"}, inplace = True)
del sl_log['ip']
sl_log = sl_log.replace(np.NaN,"")


sl_log['category']=sl_log[['src','src_info','dst','dst_info','ports']].apply(lambda x: autoanalysis(x['src'],x['src_info'],x['dst'],x['dst_info'],x['ports']),axis=1)
sl_log[sl_log['src_info'].str.contains("\|av\|") or sl_log['dst_info'].str.contains("\|av\|")]
#sl_log[sl_log['dst_info'].str.contains("\|av\|")]

#src	src norm IP	src c	src l	src info	dst	dst norm IP	dst c	dst l	dst info	direction	connects	tcp	udp	icmp	category	rule	rule_name	ports	accepted	acceptance
#sl_log.to_csv(D:\\compusafe\\Kunden\\IC_MOL_LAS_Goliath_David\\Firewall\\analysis\\firewall_logs\\' + day_str + '.log_export.txt.src-dst.csv.gz',sep = ';', encoding = 'cp1252', dtype = 'str')
export_columns = ['src', 'src_c', 'src_l', 'src_info', 'dst', 'dst_c', 'dst_l', 'dst_info', 'direction', 'connects', 'tcp', 'udp', 'icmp', 'category', 'rule', 'rule_name', 'ports', 'accepted', 'acceptance']
#D:\compusafe\Kunden\IC_MOL_LAS_Goliath_David\Firewall\analysis\firewall_logs\2020-08-24.log_export.txt.src-dst.csv.x.gz
sl_log.to_csv('D:\\compusafe\\Kunden\\IC_MOL_LAS_Goliath_David\\Firewall\\analysis\\firewall_logs\\' + day_str + '.log_export.txt.src-dst.x.csv.gz', sep = ';', columns = export_columns, index = False)

# Report für eine Woche rückwärts

from datetime import datetime, date, time, timezone, timedelta
import time
step = 1
i = 7
while i > 0:
    d = date.today() - timedelta(i)
    day_str=d.isoformat()
    print(day_str)
    #do something
    i = i - step


#

#from netaddr import IPNetwork, IPAddress, AddrFormatError
import ipaddress as iplib

network_df = pd.DataFrame([
    {'network': '1.0.0.0/24', 'A': 1, 'B': 2},
    {'network': '5.46.8.0/23', 'A': 3, 'B': 4},
    {'network': '78.212.13.0/24', 'A': 5, 'B': 6}
])
ip_df = pd.DataFrame([{'ip': '1.0.0.10'}, {'ip': 'blahblahblah'}, {'ip': '78.212.13.249'}])
# create all networks using netaddr
networks = (IPNetwork(n) for n in network_df.network.to_list())


def find_network(ipstr):
    # return empty string when bad/wrong IP
    try:
        ipstr = ip4address(ip)
    except AddrFormatError:
        return ''
    # return network name as string if we found network
    for network in networks:
        if ip_address in network:
            return str(network.cidr)
    return ''


# add network column. set network names by ip column
ip_df['network'] = ip_df['ip'].apply(find_network)
# just merge by network columns(str in both dataframes)
result = pd.merge(ip_df, network_df, how='left', on='network')
# you don't need network column in expected output...
result = result.drop(columns=['network'])
print(result)

#### Extract IPs ##############################################

import re


def extractIPs(fileContent):
    pattern = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([ (\[]?(\.|dot)[ )\]]?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})"
    ips = [each[0] for each in re.findall(pattern, fileContent)]   
    for item in ips:
        location = ips.index(item)
        ip = re.sub("[ ()\[\]]", "", item)
        ip = re.sub("dot", ".", ip)
        ips.remove(item)
        ips.insert(location, ip) 
    return ips


myFile = open(r'd:\php\tracert.txt')
fileContent = myFile.read()

IPs = extractIPs(fileContent)
print ("Original file content:\n{0}".format(fileContent))
print ("--------------------------------")
print ("Parsed results:\n{0}".format(IPs))


################# tracloc Ersatz #######################################
from netaddr import IPNetwork, IPAddress, AddrFormatError


network_df = pd.DataFrame([
    {'network': '1.0.0.0/24', 'A': 1, 'B': 2},
    {'network': '5.46.8.0/23', 'A': 3, 'B': 4},
    {'network': '78.212.13.0/24', 'A': 5, 'B': 6}
])
ip_df = pd.DataFrame([{'ip': '1.0.0.10'}, {'ip': 'blahblahblah'}, {'ip': '78.212.13.249'}])
# create all networks using netaddr
networks = (IPNetwork(n) for n in network_df.network.to_list())


def find_network(ip):
    # return empty string when bad/wrong IP
    try:
        ip_address = IPAddress(ip)
    except AddrFormatError:
        return ''
    # return network name as string if we found network
    for network in networks:
        if ip_address in network:
            return str(network.cidr)
    return ''


# add network column. set network names by ip column
ip_df['network'] = ip_df['ip'].apply(find_network)
# just merge by network columns(str in both dataframes)
result = pd.merge(ip_df, network_df, how='left', on='network')
# you don't need network column in expected output...
result = result.drop(columns=['network'])
print(result)
#               ip    A    B
# 0       1.0.0.10  1.0  2.0
# 1   blahblahblah  NaN  NaN
# 2  78.212.13.249  5.0  6.0


######################################################################
# Network
######################################################################

import socket
hostname = 'scd.siemens.de'
ip_address = socket.gethostbyname(hostname)
ip_address



from nslookup import Nslookup
domain = "ad001.siemens.net"
dns_query = Nslookup(dns_servers=["129.103.99.139"])
ips_record = dns_query.dns_lookup(domain)
print(ips_record.answer)
print(ips_record.response_full, ips_record.answer)
soa_record = dns_query.soa_lookup(domain)
print(soa_record.response_full, soa_record.answer)

import dns.resolver
dns_resolver = dns.resolver.Resolver()
dns_resolver.nameservers[0]

#wenn diese Datei fertig ist kann man abholen!
#\\139.23.160.99\d$\projects\se\se_analysis\se_cofw_logs


import pandas as pd
from io import StringIO
from datetime import datetime, date, time, timezone, timedelta
import time

d = date.today()
today = d.isoformat()
today
y = date.today() - timedelta(1)
yesterday = y.isoformat()
yesterday

#get ipam content
import requests
quote_page = ['https://coix.siemens.com/ipmgmt/?obj=ipnet']
username = 'a.scholz'
password = '7-Selectos-7'
for url in quote_page:
   ipam_content=requests.get(url, auth=(username, password),verify=False).content

ipam_content


#https://docs.python.org/2.4/lib/standard-encodings.html
import pandas as pd
import re # Regex lib
#ipman = pd.read_csv('D:\\compusafe\\Kunden\\pg\\00_gp_ip\\ipnet.csv',delimiter=';', encoding='cp1252' )
#snic = pd.read_csv('d:\\snic\\20201212-snic_ip_network_assignments.csv',delimiter=';', encoding='latin_1',engine='python' )
#snic[(snic.Location == "NKG")&(snic.Country=="CN")]
#snic = pd.read_csv('d:\\snic\\20210221-snic_ip_network_assignments.csv',delimiter=';', encoding='latin_1',engine='python' )
snic.columns = [c.replace(' ', '_') for c in snic.columns]
snic.columns = [c.replace('-', '_') for c in snic.columns]
snic.columns = [c.replace('/', '_') for c in snic.columns]
snic[(snic.VPN_name == 'Express VPN') & (1==1)]

#seek IP Ranges for Country and Location in SNIC
newdf = snic[snic.apply(lambda x: x["Country"] == 'DE' and x["Location"] == 'FFM KL', axis=1)]

#seek IP in SNIC
import ipaddress as iplib
ipstr='10.10.0.12'
snic[snic.apply(lambda x: iplib.ip_network(ipstr).subnet_of(iplib.ip_network(str(x['IP_range_CIDR']))), axis=1)].T
ipl = pd.read_clipboard()
for ipstr in ipl['ip']:
   print(snic[snic.apply(lambda x: iplib.ip_network(ipstr).subnet_of(iplib.ip_network(str(x['IP_range_CIDR']))), axis=1)]['Location'])


snic[snic['ip'] == iplib.ip_network(ipstr).subnet_of(iplib.ip_network(str(snic['IP_range_CIDR'])))]

iplib.ip_network('10.36.184.1').subnet_of(iplib.ip_network('10.36.184.0/24'))

snic[snic['ip'] == iplib.ip_network(snic['ip']).subnet_of(iplib.ip_network(snic['IP_range_CIDR']))]

#i=snic[snic.apply(lambda x: iplib.ip_network(ipstr).subnet_of(iplib.ip_network(str(x['IP_range_CIDR']))), axis=1)]
#i.T #i transponiert!


ip_red_unique = pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2020-12-11.log_export_red.txt.src-dst.csv.unique.ips.csv.gz',delimiter=';',encoding='cp1252')
ip_blue_unique = pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2020-12-11.log_export_blue.txt.src-dst.csv.unique.ips.csv.gz',delimiter=';',encoding='cp1252')
ip_unique=pd.concat([ip_red_unique,ip_blue_unique],ignore_index=True)
ip_unique=ip_unique.drop_duplicates(subset=['normed IP'])
ip_unique=ip_unique.rename(columns={"normed IP": "NormIP"})
ip_unique_merged_left = pd.merge(left=ip_unique, right=sxx, how='left', left_on='NormIP', right_on='NormIP')
ip_unique_merged_left_2 = ip_unique_merged_left.drop(['Info','IP_y','Country_y','Location_y','color'], 1)
ip_unique_merged_left_2 = ip_unique_merged_left_2.sort_values('NormIP')
ip_unique_merged_left_2
ip_unique_merged_left_2.loc[ip_unique_merged_left_2['info'] == 'office']
print(ip_unique_merged_left_2.dropna(subset=['info'])) #Ausgabe mit Info <> NaN
del(s0,s1,s2)




################### process unique ip files from php scripts
ip_unique_blue =pd.read_csv(ip_unique_yesterday_blue,delimiter=';',encoding = 'cp1252')
ip_unique_red =pd.read_csv(ip_unique_yesterday_red,delimiter=';',encoding = 'cp1252')
ip_unique=pd.concat([ip_unique_red,ip_unique_blue],ignore_index=True)
ip_unique=ip_unique.drop_duplicates(subset=['normed IP'])
del ip_unique['color']
del ip_unique['Status']
del ip_unique['Info']
grey_ip = pd.merge(grey['src'],grey['dst'],left_index=True, right_index=True)
pd.concat([s1, s2], axis=1)
grey_log_merged = pd.merge(left=grey, right=ip_unique, left_on='src', right_on='IP')
log_merged = pd.merge(left=log, right=ip_unique, left_on='src', right_on='IP')
log_merged = pd.merge(left=log, right=ip_unique, left_on='dst', right_on='IP')
ly = pd.read_csv(log_file_yesterday,sep=';')
ly[ly.rule_name=='grey_red2blue']
grey = ly[ly.rule_name=='grey_red2blue']
grey_dst=grey.dst
grey_dst
ip_dst_unique=grey_dst.unique()
df = pd.DataFrame(data=ip_dst_unique.flatten())
df.to_csv('ip.csv',sep=';')



#SE Log Analysis
#Read log analysis file
log = pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2020-12-15.log_export_red.txt.src-dst.csv.gz',delimiter=';')
#filter grey_rules
log = log[log['rule_name']=='grey_red2blue']
#read blue IP unique
ip_blue_unique =pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2020-12-15.log_export_blue.txt.src-dst.csv.unique.ips.csv.gz',delimiter=';',encoding = 'cp1252')
#read red IP unique
ip_red_unique =pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2020-12-15.log_export_red.txt.src-dst.csv.unique.ips.csv.gz',delimiter=';',encoding = 'cp1252')
#combine red & blue
ip_unique=pd.concat([ip_red_unique,ip_blue_unique],ignore_index=True)

log_merged = pd.merge(left=log, right=ip_unique, left_on='src', right_on='IP')
log_merged = pd.merge(left=log, right=ip_unique, left_on='dst', right_on='IP')



l = pd.read_csv('D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\2020-11-22.log_export_red.txt.src-dst.csv.gz',sep=';')
#pip install xlrd
#pip install pyxlsb
from pyxlsb import open_workbook as open_xlsb
#engine='pyxlsb'
fw = pd.read_excel('D:\\compusafe\\Kunden\\pg\\00_cofw\\policies\\2020-11-20_se_ruleset_v027_released.xlsb', sheet_name='all_red_networks' , engine='pyxlsb')
d.strftime("%A %d. %B %Y")
filename = d.strftime("D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\%Y-%m-%d.log_export_red.txt.src-dst.csv.gz")
filename

log_file_yesterday = y.strftime("D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\%Y-%m-%d.log_export_red.txt.src-dst.csv.gz")

#https://docs.python.org/3/library/ipaddress.html
import ipaddress as iplib
int(iplib.IPv4Address('10.0.0.0'))
IPv4Address('127.0.0.2') + 1
iplib.ip_address(3221225985)
iplib.IPv4Address('127.0.0.2') > iplib.IPv4Address('127.0.0.1')
iplib.IPv4Address('127.0.0.2') == iplib.IPv4Address('127.0.0.1')
iplib.IPv4Address('127.0.0.2') != iplib.IPv4Address('127.0.0.1')
list(iplib.ip_network('192.0.2.0/29').hosts())  
a = iplib.ip_network('192.168.1.0/24')
b = iplib.ip_network('192.168.1.128')
b.subnet_of(a)

snic.rename(columns={'IP range/CIDR':'IP_range_CIDR'}, inplace=True) 
snic[10000:10022]

https://pandas.pydata.org/pandas-docs/stable/user_guide/merging.html

pd.set_option('display.max_rows', 40)
pd.set_option('display.max_columns', 200)
pd.set_option('display.width', 1000)


#sysdb = sysdb.style.set_properties(**{'text-align': 'left'}) 
 

import pandas as pd

def read_excel_sheets(xls_path):
    """Read all sheets of an Excel workbook and return a single DataFrame"""
    print(f'Loading {xls_path} into pandas')
    xl = pd.ExcelFile(xls_path)
    df = pd.DataFrame()
    columns = None
    for idx, name in enumerate(xl.sheet_names):
        print(f'Reading sheet #{idx}: {name}')
        sheet = xl.parse(name)
        if idx == 0:
            # Save column names from the first sheet to match for append
            columns = sheet.columns
        sheet.columns = columns
        # Assume index of existing data frame when appended
#        df = df.append(sheet, ignore_index=True)
    return df
#
#
x=read_excel_sheets(r'D:\compusafe\Kunden\pg\00_cofw\policies\2021-03-12_se_ruleset_v040_released.xlsb')



#################### snic ########################################
import pandas as pd
import ipaddress as iplib
import xlwt
import openpyxl

snic = pd.read_csv(r"d:\snic\20210314-snic_ip_network_assignments.csv",sep = ';',encoding = "latin-1")

def get_ip_range(ipstr,snicdb): #erste Variable steht für Wert aus DataFrame, zweiter Wert steht für Variable
    ip = iplib.ip_address(ipstr)
    for x in snic['IP range/CIDR']:
        if ip in iplib.IPv4Network(x, strict=True):
            return x 
    return "no SNIC-DB entry"

#snic['ip_net_base_bin'] = snic['IP-net-base'].apply(lambda x: int(iplib.IPv4Address(x)))
#snic['ip_net_top_bin'] = snic['IP-net-top'].apply(lambda x: int(iplib.IPv4Address(x)))

#ip = iplib.IPv4Address(ip_str)
#ipl = pd.read_excel(r'E:\python\ip_suchen.xls',sheet_name='ipl')
ipl['x'] = ipl['ip'].apply(lambda x: get_ip_range(x,snic))
ipl
iplx = pd.merge(left=ipl, right=snic, left_on='x', right_on='IP range/CIDR')
iplx.to_clip_board(index = None)


################## Backup Server connections ###############################################
#
#ipl
#146.254.43.218
#146.254.43.219
#146.254.43.220
backup_server_connections = pd.merge(left = log, right = ipl, how='left', left_on='src', right_on='ip')
#.to_csv(r'd:\tmp\backup_server_connections_2021-03-16.csv.gz',sep = ';', encoding = 'cp1252')
sysdb_p1 = sysdb[['ip','c','l','ip_cidr']]
backup_server_connections_x = pd.merge(left = backup_server_connections, right = sysdb_p1 , how='left', left_on='dst', right_on='ip')#.to_csv(r'd:\tmp\backup_server_connections_2021-03-16.csv.gz',sep = ';', encoding = 'cp1252')
backup_server_connections_x = backup_server_connections_x.drop_duplicates(subset=['ip_cidr'])




#sysdb16 =pd.read_csv(r'D:\php\sysdb_2021-03-16.gz', delimiter=';',dtype='str',encoding='utf-8')

##################### tracloc Ersatz #################################
tracloc = pd.read_text(r'D:\php\tracert.txt', sep = '~')
tracloc[0][tracloc[0].str.contains('ms')]
######################################################################
import re

with open(r'd:\php\tracert.txt', 'r') as file:
    fi = file.readlines()


re_ip = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
re_port = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/(\d+)")

for line in fi:
#    port = re.findall(re_port,line)
    ip = re.findall(re_ip,line)
#    print ("PORT is  " , port , "ip is " ,ip)
    print (line.rstrip(), ";" ,ip)

#



import sys
import re

try:
    if sys.argv[1:]:
        print "File: %s" % (sys.argv[1])
        logfile = sys.argv[1]
    else:
        logfile = raw_input("Please enter a log file to parse, e.g /var/log/secure: ")
    try:
        file = open(logfile, "r")
        ips = []
        for text in file.readlines():
           text = text.rstrip()
           regex = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})$',text)
           if regex is not None and regex not in ips:
               ips.append(regex)

        for ip in ips:
           outfile = open("/tmp/list.txt", "a")
           addy = "".join(ip)
           if addy is not '':
              print "IP: %s" % (addy)
              outfile.write(addy)
              outfile.write("\n")
    finally:
        file.close()
        outfile.close()
except IOError, (errno, strerror):
        print "I/O Error(%s) : %s" % (errno, strerror)
#


################### finde/lösche werte in sysdb ###########################################
sysdb[~sysdb.ip.str.contains('\.')] # löscht alle Werte die in ip einen Punkt haben
sysdb = sysdb[sysdb.ip.str.contains('\.')] # überträgt alle Werte die in ip einen Punkt haben

################### sysdb fast info ######################################################

sysdb.loc[sysdb['ip'] == '146.254.11.79'].to_clipboard(index = None)

#ipl = pd.read_clipboard()
ipl = pd.merge(left = ipl, right=sysdb, how='left', left_on='ip', right_on='ip')
ipl.to_clipboard(index = None)

#get-snic-values
ipl['ip_cidr'] = ipl.apply(lambda x: get_ip_range(x['ip']) , axis=1)
snic_reduced = snic[['Country','Location','Comment','IP range/CIDR']]
ipl = pd.merge(left = ipl, right=snic_reduced, how='left', left_on='ip_cidr', right_on='IP range/CIDR')
ipl['c'] = ipl['Country']
ipl['l'] = ipl['Location']
ipl['snic_comment'] = ipl['Comment']
del ipl['Country']
del ipl['Location']
del ipl['Comment']
del ipl['IP range/CIDR']
ipl['info'] = ipl['sys_type'] + '|' + ipl['dns'] + '|' + ipl['corpflag'] + '|' + ipl['info_extra'] + '|' + ipl['managed_by_mail'] + '|' + ipl['description'] + '|' + ipl['snic_comment'] + '|' + ipl['ip_cidr'] + '|' + ipl['c'] + '|' + ipl['l']

#ipl add ipman data
ipl = pd.merge(left = ipl, right=ipman, how='left', left_on='ip', right_on='ip_net_base')
ipl.to_clipboard(index = None)


#get-dns-values by Log-Server
import subprocess
ipl['ip'].to_csv(r'\\139.23.160.99\d$\powershell\ip.txt', index = False, header = False)
cmd = 'Invoke-Command -ComputerName DEFTHW99M5BSRV -FilePath d:\powershell\get-dns-by-ips.ps1'
completed = subprocess.run(["powershell", "-Command", cmd])
dns = pd.read_csv(r'\\139.23.160.99\d$\powershell\dns.csv',sep=';') #get dns after running get-dns-by-ips.ps1
ipl['dns'] = dns['DNS'].values  # add column of \\139.23.160.99\d$\powershell\dns.csv to ipl
ipl.replace('DNS n/a','', inplace=True)
#fill info field
ipl['info'] = ipl['sys_type'] + '|' + ipl['dns'] + '|' + ipl['corpflag'] + '|' + ipl['info_extra'] + '|' + ipl['managed_by_mail'] + '|' + ipl['description'] + '|' + ipl['snic_comment'] + '|' + ipl['ip_cidr'] + '|' + ipl['c'] + '|' + ipl['l']


import subprocess
cmd = 'net view \\\\158.226.210.30 /all'
completed = subprocess.run(["powershell", "-Command", cmd], capture_output=True)



############################################# sysdb_maintain ######################################################
############################################# sysdb_maintain ######################################################
############################################# sysdb_maintain ######################################################
import pandas as pd
import numpy as np
from datetime import datetime, date, time, timezone, timedelta
import time

d = date.today()
today = d.isoformat()
today
y = date.today() - timedelta(1)
yesterday = y.isoformat()
yesterday

#yesterday = '2021-08-20'
#today = '2021-08-21'

#sysdb = pd.read_csv(r'D:\php\sysdb_'+today+'.gz',delimiter=';',encoding='utf-8',dtype='str')
#sysdb = pd.read_csv(r'D:\php\sysdb_'+yesterday+'.gz',delimiter=';',encoding='utf-8',dtype='str')


sysdb.replace(np.NaN,'-', inplace=True)
maintain = pd.read_excel(r'D:\python\sysdb_maintain.xlsm', sep = ';', sheet_name = 'sysdb_new_systems', encoding = 'cp1252', dtype = 'str')
maintain.replace(np.NaN,'-', inplace=True)
maintain['last_modified'] = today
maintain = maintain[maintain['ip'] != 'ip'] #erase lines with ip==ip
maintain.drop(maintain.iloc[:, 24:], inplace = True, axis = 1) #24 column limit
#maintain

################### update SNIC values ############################################
maintain['ip_cidr'] = maintain.apply(lambda x: get_ip_range(x['ip']) , axis=1)
snic_reduced = snic[['Country','Location','Comment','IP range/CIDR','VPN name']]
maintain = pd.merge(left = maintain, right=snic_reduced, how='left', left_on='ip_cidr', right_on='IP range/CIDR')
maintain['c'] = maintain['Country']
maintain['l'] = maintain['Location']
maintain['snic_comment'] = maintain['Comment']
maintain['vpn_name'] = maintain['VPN name']

del maintain['Country']
del maintain['Location']
del maintain['Comment']
del maintain['IP range/CIDR']
del maintain['VPN name']
maintain.replace(np.NaN,'-', inplace=True)
maintain
#sysdb
#Achtung alle IPs aus maintain werden mit allen infos gelöscht
sysdb = sysdb[~sysdb.ip.isin(maintain.ip)] #delete all maintain.ip in sysdb

#add new maintain info to sysdb
sysdb = pd.concat([sysdb,maintain],ignore_index=True)

#sysdb[sysdb.ip.isin(maintain.ip)] # check if new values in sysdb
sysdb['info'] = sysdb['sys_type'] + '|' + sysdb['dns'] + '|' + sysdb['corpflag'] + '|' + sysdb['info_extra'] + '|' + sysdb['managed_by_mail'] + '|' + sysdb['description'] + '|' + sysdb['snic_comment'] + '|' + sysdb['ip_cidr'] + '|' + sysdb['c'] + '|' + sysdb['l']

#update region field
region = pd.read_csv('d:\\tmp\\region.csv',sep = ';')
sysdb =  pd.merge(left = sysdb, right=region, how='left', left_on='c', right_on='c')
sysdb['region_x'] = sysdb['region_y']
del (sysdb['region_y'])
sysdb = sysdb.rename(columns={'region_x': 'region'})

sysdb = sysdb.replace(np.NaN,"")
sysdb.tail(50)
#delete list of ip from clipboard
#ipl = pd.read_clipboard(header=None,names=['ip'])
#sysdb = sysdb[~sysdb.ip.isin(ipl.ip)] #delete all maintain.ip in sysdb
#sysdb[sysdb['ip'] != '139.23.212.205']

#delete column 24
#sysdb.drop(sysdb.columns[[24]], axis = 1, inplace = True)
#
#store sysdb to csv
#sysdb.to_csv(r'd:\php\sysdb_'+today+'.gz', sep = ';', index = False, encoding = 'utf-8')
#sysdb.to_csv(r'd:\php\sysdb_'+yesterday+'.gz', sep = ';', index = False, encoding = 'utf-8')
#sysdb.drop(sysdb.iloc[:, 24:], inplace = True, axis = 1)

############################################# sysdb_maintain end ###################################################
############################################# sysdb_maintain end ###################################################


############################################# sysdb quality checks #################################################
############################################# sysdb quality checks #################################################
############################################# sysdb quality checks #################################################
#Filter rows w/o IP Range
sysdb[(sysdb['ip_cidr'] == '') & (sysdb['c'] != 'no SNIC-DB entry found') & (sysdb['c'] != 'Internet')].drop_duplicates(subset=['ip'])
sysdb[(sysdb['c']=='-') & (sysdb['ip_cidr']!='no SNIC-DB entry')]
###### sysdb: seek for invalid IPs ########################
sysdb_ip_invalid = sysdb[~sysdb['ip'].str.contains('^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$')]
sysdb = sysdb[sysdb['ip'].str.contains('^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$')]

sysdb_ip_invalid.to_clipboard(index = None)

###################### maintain sysdb ip_cidr start #####################
###################### maintain sysdb ip_cidr start #####################
###################### maintain sysdb ip_cidr start #####################

sysdb
startTime = time.time()
sysdb['ip_cidr'] = sysdb.apply(lambda x: get_ip_range(x['ip']) , axis=1)
snic_reduced = snic[['Country','Location','Comment','IP range/CIDR']]
sysdb = pd.merge(left = sysdb, right=snic_reduced, how='left', left_on='ip_cidr', right_on='IP range/CIDR')
sysdb['c'] = sysdb['Country']
sysdb['l'] = sysdb['Location']
sysdb['snic_comment'] = sysdb['Comment']
del sysdb['Country']
del sysdb['Location']
del sysdb['Comment']
del sysdb['IP range/CIDR']
sysdb.replace(np.NaN,'-', inplace=True)
sysdb['info'] = sysdb['sys_type'] + '|' + sysdb['dns'] + '|' + sysdb['corpflag'] + '|' + sysdb['info_extra'] + '|' + sysdb['managed_by_mail'] + '|' + sysdb['description'] + '|' + sysdb['snic_comment'] + '|' + sysdb['ip_cidr'] + '|' + sysdb['c'] + '|' + sysdb['l']
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))
sysdb

###################### maintain sysdb ip_cidr end #######################
###################### maintain sysdb ip_cidr end #######################
###################### maintain sysdb ip_cidr end #######################

grey_log_merged[grey_log_merged['dst']=='139.22.154.252']
grey_log_merged[grey_log_merged['dst']=='149.212.92.23']#.to_clipboard(index = None)

# delete single ip value 
sysdb = sysdb[sysdb['ip']!='129.214.187.206']
# delete column by number
sysdb.drop(sysdb.columns[[24]], axis = 1, inplace = True)



################# fill maintain excel wit current sysdb data ### 

import pandas as pd
import numpy as np
import ipaddress as iplib #ip.
import glob
from datetime import datetime, date, time, timezone, timedelta
import time
from my_functions import *

import socket
import struct
#from my_functions import *

d = date.today() #- timedelta(0)  #today #today = d.isoformat()
y = date.today() - timedelta(1) #yesterday#yesterday = y.isoformat()

today = d.isoformat()
yesterday = y.isoformat()

############################### Datum verschieben ###########
#today     = '2021-03-13'
#yesterday = '2021-03-12'
############################### Datum verschieben ###########

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

#get latest snic-db, add binary values
snicfiles=glob.glob(r'D:\snic\*-snic_ip_network_assignments.csv')
print('load latest SNIC file: ' + snicfiles[-1])
snic = pd.read_csv(snicfiles[-1],sep = ';',encoding = "latin-1", dtype = 'str')
snic['ip_base_bin'] = snic['IP-net-base'].apply(lambda x: ip2int(x))
snic['ip_top_bin'] = snic['IP-net-top'].apply(lambda x: ip2int(x))

def get_ip_range(istr):
    ipbin = ip2int(istr)
    ip_range_row = snic.loc[(ipbin >= snic['ip_base_bin'] ) & (ipbin <= snic['ip_top_bin']), ['IP range/CIDR']]
    if ip_range_row.empty == True:
        ip_range = 'no SNIC-DB entry'
    else:
        ip_range = ip_range_row.iat[0,0]
    return ip_range

def get_latest_sysdb():
    files=glob.glob(r'D:\php\sysdb*.gz')
    print('load latest sysdb file: ' + files[-1])
    sysdb = pd.read_csv(files[-1],sep = ';',encoding = "utf-8", dtype = 'str')
    return sysdb

if not 'sysdb' in dir():
    sysdb = get_latest_sysdb()


sysdb.replace(np.NaN,'-', inplace=True)
maintain = pd.read_excel(r'D:\python\sysdb_maintain.xlsm', sep = ';', sheet_name = 'sysdb_new_systems', encoding = 'cp1252', dtype = 'str')
maintain.replace(np.NaN,'-', inplace=True)
maintain['last_modified'] = today
maintain
################### SNIC maintaining ############################################
maintain['ip_cidr'] = maintain.apply(lambda x: get_ip_range(x['ip']) , axis=1)
snic_reduced = snic[['Country','Location','Comment','IP range/CIDR']]
maintain = pd.merge(left = maintain, right=snic_reduced, how='left', left_on='ip_cidr', right_on='IP range/CIDR')
maintain['c'] = maintain['Country']
maintain['l'] = maintain['Location']
maintain['snic_comment'] = maintain['Comment']
del maintain['Country']
del maintain['Location']
del maintain['Comment']
del maintain['IP range/CIDR']
maintain
maintain.to_clipboard(index = None, header = None)


####################### ipman #################################################

ipman = pd.read_csv(r'D:\tmp\ipnet.csv',delimiter=';', encoding='cp1252' )
ipman = ipman.replace('&sect;','&')


############### blue2red Auswertung, cloud, dc ########################################
############### blue2red Auswertung, cloud, dc ########################################
############### blue2red Auswertung, cloud, dc ########################################

#day_str = '2021-06-23'
day_str = '2021-08-31'

express_fw_clusters = pd.read_excel(r'D:\python\express_fw_clusters.xlsx')
se_fw_clusters = pd.read_excel(r'D:\python\se_fw_clusters.xlsx')

log_dir = 'D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\'  #SE
log_dir = 'D:\\compusafe\\Kunden\\mobility\\00_firewall_cofw\\analysis\\'    #Express
log_file_blue = log_dir + day_str + '.log_export_blue.txt.src-dst.csv.gz'
blue2red = pd.read_csv(log_file_blue, sep = ';', encoding = 'cp1252',dtype = 'str')
blue2red_x = pd.merge(left = blue2red, right = sysdb[['ip','c','l','info','ip_cidr']], how='left', left_on='src', right_on='ip')
blue2red_x = pd.merge(left = blue2red_x, right = sysdb[['ip','c','l','info','ip_cidr']], how='left', left_on='dst', right_on='ip')
blue2red_x.rename(columns={'c_x': 'src_c', 'l_x': 'src_l', 'info_x': 'src_info','c_y': 'dst_c', 'l_y': 'dst_l', 'info_y': 'dst_info'},inplace = True)
#blue2red.sort_values('connects', ascending = False, inplace = True)
blue2red_x = pd.merge(left = blue2red_x, right = express_fw_clusters[['c','HUB DC']], left_on = 'dst_c', right_on = 'c', how = 'left')
blue2red_x = blue2red_x.replace(np.NaN,'-')
del (blue2red_x['ip_x'])
del (blue2red_x['ip_y'])
del (blue2red_x['ip_cidr_x'])
del (blue2red_x['ip_cidr_y'])
del (blue2red_x['c'])

log_file_red = log_dir + day_str + '.log_export_red.txt.src-dst.csv.gz'
red2blue = pd.read_csv(log_file_red, sep = ';', encoding = 'cp1252',dtype = 'str')
red2blue_x = pd.merge(left = red2blue, right = sysdb[['ip','c','l','info','ip_cidr']], how='left', left_on='src', right_on='ip')
red2blue_x = pd.merge(left = red2blue_x, right = sysdb[['ip','c','l','info','ip_cidr']], how='left', left_on='dst', right_on='ip')
red2blue_x.rename(columns={'c_x': 'src_c', 'l_x': 'src_l', 'info_x': 'src_info','c_y': 'dst_c', 'l_y': 'dst_l', 'info_y': 'dst_info'},inplace = True)
#red2blue.sort_values('connects', ascending = False, inplace = True)
red2blue_x = pd.merge(left = red2blue_x, right = express_fw_clusters[['c','HUB DC']], left_on = 'src_c', right_on = 'c', how = 'left')
red2blue_x = red2blue_x.replace(np.NaN,'-')
del (red2blue_x['ip_x'])
del (red2blue_x['ip_y'])
del (red2blue_x['ip_cidr_x'])
del (red2blue_x['ip_cidr_y'])
del (red2blue_x['c'])

log_combi_x = pd.concat([blue2red_x, red2blue_x], ignore_index = True)
log_combi_x

startTime = time.time()
log_combi_x['category']=log_combi_x[['src','src_info','dst','dst_info','ports']].apply(lambda x: autoanalysis(x['src'],x['src_info'],x['dst'],x['dst_info'],x['ports']),axis=1)
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))


log_combi_x.rename(columns={'HUB DC': 'fw_loc'},inplace = True)
log_combi_x = log_combi_x[['src','src_c','src_l','src_info','dst','dst_c','dst_l','dst_info','ports','connects','orig','direction','fw_loc','category']]

log_combi_x = log_combi_x.astype({"connects": int})
log_combi_x.sort_values('connects', ascending = False, inplace = True)
log_combi_x

#log_combi_x[['src_c','dst_c','orig','fw_loc','direction']].head(55)
log_dc = log_combi_x[(log_combi_x.src_info.str.contains('^dc',case = False)) | (log_combi_x.dst_info.str.contains('^dc',case = False))]
log_dc = log_dc[log_dc['src_c'] != '-'] #rausfiltern unknown in SNIC
log_dc = log_dc[log_dc['dst_c'] != '-'] #rausfiltern unknown in SNIC
log_dc

log_dc.to_excel('d:\\tmp\\ ' + day_str + '_dc_traffic.xlsx', sheet_name = 'dc_traffic' , encoding = 'cp1252', columns = ['src','src_c','src_l','src_info','dst','dst_c','dst_l','dst_info','ports','connects','orig','direction','category','fw_loc'],index = None)

cloud = log_combi_x[log_combi_x['dst_info'].str.contains('(Azur|cloud|AWS)',case = False)]
cloud = cloud[~cloud['dst_info'].str.contains('Shawson',case = False)]

############### blue2red Auswertung, cloud, dc end ########################################
############### blue2red Auswertung, cloud, dc end ########################################
############### blue2red Auswertung, cloud, dc end ########################################

############### ECD #########################################################
ecd = pd.read_excel(r'D:\compusafe\Kunden\pg\baselining\se_iam_2024-04-26.xlsx')
ecd.replace(np.NaN,'-', inplace = True)
ecd[ecd['mail'].str.contains('Bluschke', case = False)]

############## SAL Codes ##############################################
sal = pd.read_csv(r'D:\tmp\Reports_Network_Information_Center_SNIC_sal_nic_location.txt',encoding = 'cp1252', sep = '!')


merlin[merlin['SAL']=='OSL']['MIG Overall Status']
#146.253.86.28
grey_log_merged[grey_log_merged['dst']=='139.21.179.116']#.to_clipboard(index = None)
grey_log_merged[grey_log_merged['category']=='0_app-teamcenter']#.head(50)
grey_log_merged[grey_log_merged['dst_info'].str.contains('teamcenter')]#.head(50)
grey_log_merged[grey_log_merged['src_info'].str.contains('zpa')]#.head(50)
grey_log_merged[grey_log_merged['category'].str.contains('^0_app')].connects.sum()

sysdb.loc[sysdb['ip'] == '141.73.21.216'].to_clipboard()


ecd = pd.read_csv(r'D:\compusafe\Kunden\pg\baselining\se_iam_2024-04-26.xlsx', sep = ';', )

##### weekly logs ##################################
week_log_x[week_log_x['ports'].str.contains('_88,')]
week_log_x[week_log_x['ports'].str.contains('_8080,')]


#sysdb[sysdb['info'].str.contains("router")]#10.141.182.31

######## async routing ar ##############################################
#bash cli: zcat /mnt/m/server_defthw99m5bsrv/dlw/projects/se/se_cofw_logs/2021-05-03*.log_export.txt.gz | grep -E '(;First|num)' > /mnt/d/tmp/first_packet_isnt-syn_2021-05-03.csv
ar = pd.read_csv(r'D:\tmp\first_packet_isnt-syn_2021-05-03.csv',sep = ';', encoding = 'cp1252')
ar = ar[('i/f_name','src','dst')]
ar['pair'] = ar['src'] +';'+ar['dst']
ar.drop_duplicates(subset=['pair'])
ar.drop_duplicates(subset=['pair'],inplace = True)
ar = ar.reset_index(drop=True)
ar = ar[ar['i/f_name']!='i/f_name']
startTime = time.time()
ar['src_ip_cidr'] = ar.apply(lambda x: get_ip_range(x['src']) , axis=1)
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))
startTime = time.time()
ar['dst_ip_cidr'] = ar.apply(lambda x: get_ip_range(x['dst']) , axis=1)
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))
ar['cidr_pair'] = ar['src_ip_cidr'] +';'+ar['dst_ip_cidr']
ar_cidr_pair_unique = ar.drop_duplicates(subset=['cidr_pair'])
ar_cidr_pair_unique = (snic_reduced)

snic_reduced = snic[['Country','Location','Comment','IP range/CIDR']]
ar_cidr_pair_unique = pd.merge(left = ar_cidr_pair_unique, right=snic_reduced, how='left', left_on='src_ip_cidr', right_on='IP range/CIDR')
ar_cidr_pair_unique['src_c'] = ar_cidr_pair_unique['Country']
ar_cidr_pair_unique['src_l'] = ar_cidr_pair_unique['Location']
#ar_cidr_pair_unique['snic_comment'] = ar_cidr_pair_unique['Comment']
del ar_cidr_pair_unique['Country']
del ar_cidr_pair_unique['Location']
del ar_cidr_pair_unique['Comment']
del ar_cidr_pair_unique['IP range/CIDR']
ar_cidr_pair_unique


ar_cidr_pair_unique = pd.merge(left = ar_cidr_pair_unique, right=snic_reduced, how='left', left_on='dst_ip_cidr', right_on='IP range/CIDR')
ar_cidr_pair_unique['dst_c'] = ar_cidr_pair_unique['Country']
ar_cidr_pair_unique['dst_l'] = ar_cidr_pair_unique['Location']
#ar_cidr_pair_unique['snic_comment'] = ar_cidr_pair_unique['Comment']
del ar_cidr_pair_unique['Country']
del ar_cidr_pair_unique['Location']
del ar_cidr_pair_unique['Comment']
del ar_cidr_pair_unique['IP range/CIDR']
ar_cidr_pair_unique
ar_cidr_pair_unique_reduced = ar_cidr_pair_unique[['src_ip_cidr','src_c','src_l','dst_ip_cidr','dst_c','dst_l']]
ar_cidr_pair_unique_reduced.to_csv(r'd:\tmp\async_routings_2021-05-04.csv', sep = ';', index = None)


def iplc():
    ipl = pd.read_clipboard(name='',sep = '#')
    ipl[['ip']] = ipl.ip.str.extract('(.*):(.*)', expand=True)
    ipl = pd.merge(left = ipl, right=sysdb, how='left', left_on='ip', right_on='ip')
    ipl.to_clipboard(index = None)






##################### SE blue>red log #################################################################
se_b2r = pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-05-03.log_export_blue.txt.src-dst.csv.gz', sep = ';', encoding = 'cp1252')#,dtype = str)
se_b2r.sort_values('connects', ascending = False, inplace = True)


######################## get red log file make ip unique and make ip analysis ###########################################################################
######################## get red log file make ip unique and make ip analysis ###########################################################################
######################## get red log file make ip unique and make ip analysis ###########################################################################

datestr = '2021-05-14' # Set analysis data
log_red = pd.read_csv('D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\' + datestr + '.log_export_red.txt.src-dst.csv.gz', sep = ';', encoding = 'cp1252')

log_red.replace(np.NaN,'-', inplace=True)
log_red = log_red.sort_values('connects', ascending = False)
#log_red[(log_red['src']=='129.73.83.104') & (log_red['rule_name']=='grey_red2blue')].count() # check 2 conditions
#log_red[(log_red['src']=='129.73.83.104') & (log_red['rule_name']=='grey_red2blue')]['connects'].sum()
#log_red[log_red['src']=='129.73.83.104']['ports'].str.contains('tcp_445').count()
check_red = log_red[['src','dst','connects','ports']]
check_red
red_src_count = check_red['src'].value_counts()#.to_frame() get number of src ips
red_src_count #how many pairs with this source ip!

check_red_src_unique = check_red.groupby('src',as_index=False).agg({'connects':'sum'})
check_red_src_unique = check_red_src_unique.sort_values('connects', ascending = False)
check_red_src_unique = check_red_src_unique[check_red_src_unique['src'].str.contains('.')] #delete all src IPs w/o points
check_red_src_unique['ip_cidr'] = check_red_src_unique.apply(lambda x: get_ip_range(x['src']) , axis=1) # add for each src an IP range
check_red_src_unique = pd.merge(left = check_red_src_unique, right=snic_reduced, how='left', left_on='ip_cidr', right_on='IP range/CIDR') # enrich src with snic
check_red_src_unique['ips']=1
check_red_src_unique

check_red_src_unique_sal = check_red_src_unique.groupby('Location',as_index=False).agg({'ips':'sum'})
check_red_src_unique_sal = check_red_src_unique_sal.sort_values('ips', ascending = False)

check_red_src_unique_sal = check_red_src_unique_sal.rename(columns={'Location': 'NW_Tracking_List_SAL', 'ips': 'Sum of red Source IPs'})
check_red_src_unique_sal

check_red_src_unique_sal.to_csv('D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\' + datestr + '.log_export_red.txt.src-dst.csv.analysis.csv', sep = ';', encoding = 'cp1252', index = None)
#check_red_src_freq['freq'] = check_red.groupby('src')['src'].transform('count')

########################### compute red+blue #############################################################
########################### compute red+blue #############################################################
########################### compute red+blue #############################################################

#get latest snic-db, add binary values and reduce
snicfiles=glob.glob(r'D:\snic\*-snic_ip_network_assignments.csv')
print('load latest SNIC file: ' + snicfiles[-1])
snic = pd.read_csv(snicfiles[-1],sep = ';',encoding = "latin-1", dtype = 'str')
snic['ip_base_bin'] = snic['IP-net-base'].apply(lambda x: ip2int(x))
snic['ip_top_bin'] = snic['IP-net-top'].apply(lambda x: ip2int(x))
snic.replace(np.NaN,"", inplace = True)

day_str = '2022-01-25'

files = glob.glob('M:\\server_defthw99m5bsrv\\dlw\\projects\\express\\co_fw_logs\\' + day_str + '_*.log_export.txt.gz') # Express
files = glob.glob('M:\\server_defthw99m5bsrv\dlw\\projects\\darwin\\darwin_cofw_logs\\' + day_str + '_*.log_export.txt.gz') # Darwin


for file in files:
    print(file)
    log = pd.read_csv(file, sep = ';', encoding = 'cp1252',error_bad_lines=False,warn_bad_lines=True, usecols=['type','action','i/f_name','i/f_dir','origin_id','src','dst','proto','service'],dtype='str')
    log = log[(log['type'] == 'connection') & (log['action'] == 'accept') & (log['i/f_dir'] == 'inbound')]
    del (log['type'])
    del (log['action'])
    del (log['i/f_dir'])
    log['port'] = log['proto'] + '_' + log['service']
    del (log['proto'])
    del (log['service'])
    log['origin_id'] = log['origin_id'].str[18:23]
    log['i/f_name'] = log['i/f_name'].str[-1]
    log['pair'] = log['src'] + '_' + log['dst']
    log['connects'] = 1
    log.replace(np.NaN,'-', inplace=True)
    log_agg = log.groupby('pair',as_index=False).agg({'connects':'sum'})
    log_agg = pd.merge(left = log_agg, right = log[['pair','i/f_name','origin_id']], how = 'left', on = 'pair')
    if file == files[0]:
        log_all = log_agg
    else:
        log_all = pd.concat([log_all,log_agg],ignore_index=True)

log_all_result = log_all.groupby('pair',as_index=False).agg({'connects':'sum'})

log_all_result[['src','dst']] = log_all_result.pair.str.split("_",expand=True)
log_analysis = pd.merge(left = log_all_result, right = sysdb[['ip','c','l','info','ip_cidr']], how = 'left',left_on='src', right_on='ip')
log_analysis = log_analysis.rename(columns={'c': 'src_c', 'l': 'src_l', 'info': 'src_info','ip_cidr': 'src_ip_cidr'})
del (log_analysis['ip'])
log_analysis = pd.merge(left = log_analysis, right = sysdb[['ip','c','l','info','ip_cidr']], how = 'left',left_on='dst', right_on='ip')
log_analysis = log_analysis.rename(columns={'c': 'dst_c', 'l': 'dst_l', 'info': 'dst_info','ip_cidr': 'dst_ip_cidr'})
del (log_analysis['ip'])
log_analysis.replace(np.NAN,'-',inplace = True)
log_analysis.sort_values('connects', ascending = False,inplace=True)

#filter on DHCP
log_analysis_dhcp = log_analysis[log_analysis['dst_info'].str.contains('dhcp',case=False)]
del(log_analysis_dc['pair'])
# filter on DC
log_analysis_dc = log_analysis[log_analysis['src_info'].str.contains('^dc') | log_analysis['dst_info'].str.contains('^dc')]
del(log_analysis_dc['pair'])

src_ip_cidr = log_analysis_dc.groupby('src_ip_cidr',as_index=False).agg({'connects':'sum'})
dst_ip_cidr = log_analysis_dc.groupby('dst_ip_cidr',as_index=False).agg({'connects':'sum'})

src_ip_cidr.rename(columns={'src_ip_cidr':'ip_cidr'},inplace = True)
dst_ip_cidr.rename(columns={'dst_ip_cidr':'ip_cidr'},inplace = True)

ip_cidr = pd.concat([src_ip_cidr,dst_ip_cidr],ignore_index=True)
ip_cidr = ip_cidr[ip_cidr['ip_cidr'].str.contains('/')]
ip_cidr = ip_cidr.groupby('ip_cidr',as_index=False).agg({'connects':'sum'})
#ip_cidr[['ip','cidr']] = ip_cidr.ip_cidr.str.split("/",expand=True)

ip_cidr = pd.merge(left = ip_cidr, right = snic[['IP range/CIDR','potential router ip']],how = 'left', left_on = 'ip_cidr', right_on = 'IP range/CIDR')

log_all_result.to_csv('D:\\tmp\\express_log_all_'+ day_str + '.csv.gz', sep = ';', index = None)



######### nur eine Log File auswerten #################
day_str = '2022-01-26'
files = glob.glob('M:\\server_defthw99m5bsrv\\dlw\\projects\\express\\co_fw_logs\\' + day_str + '_*.log_export.txt.gz') # Express
files = glob.glob('M:\\server_defthw99m5bsrv\dlw\\projects\\darwin\\darwin_cofw_logs\\' + day_str + '_*.log_export.txt.gz') # Darwin
#M:\server_defthw99m5bsrv\dlw\projects\darwin\darwin_cofw_logs\2021-10-27_000000.log_export.txt.gz
#log = pd.read_csv(files[0], sep = ';', encoding = 'cp1252',error_bad_lines=False,warn_bad_lines=True, usecols=['type','action','i/f_name','i/f_dir','origin_id','src','dst','proto','service'],dtype='str')
log = pd.read_csv(files[0], sep = ';', encoding = 'cp1252',error_bad_lines=False,warn_bad_lines=True,dtype='str')
log.rename(columns={'Unnamed: 11': 'rule_name'})
del(log['num'])
del(log['UP_match_table'])
del(log['TCP packet out of state'])
del(log['tcp_flags'])
del(log['alert'])
#del(log['origin_id'])
del(log['s_port'])
log = log.rename(columns={'Unnamed: 11': 'rule_name'})
log.info()
#log = log[(log['type'] == 'connection') & (log['action'] == 'accept') & (log['i/f_dir'] == 'inbound') ] #red&blue
log = log[(log['type'] == 'connection') & (log['action'] == 'accept') & (log['i/f_dir'] == 'inbound') & (log['i/f_name']=='bond2')& (log['rule_name']=='greyrule_red2blue')] #red only
del (log['type'])
del (log['action'])
del (log['i/f_dir'])
log['port'] = log['proto'] + '_' + log['service']
del (log['proto'])
del (log['service'])
log['origin_id'] = log['origin_id'].str[17:22]
log['i/f_name'] = log['i/f_name'].str[-1]
log['pair'] = log['src'] + '_' + log['dst']
log['connects'] = 1
log.replace(np.NaN,'-', inplace=True)
log.info()
log


################ get dhcp start ###########
log_dhcp = log[log.port.str.contains('_67')] #filter dhcp
log_dhcp_agg = log_dhcp.groupby('pair',as_index=False).agg({'connects':'sum'})
log_dhcp_agg.sort_values('connects', ascending = False,inplace=True)
log_dhcp_agg

log_dhcp_agg[['src','dst']] = log_dhcp_agg.pair.str.split("_",expand=True)
log_analysis = pd.merge(left = log_dhcp_agg, right = sysdb[['ip','c','l','info','ip_cidr','vpn_name']], how = 'left',left_on='src', right_on='ip')
log_analysis = log_analysis.rename(columns={'c': 'src_c', 'l': 'src_l', 'info': 'src_info','ip_cidr': 'src_ip_cidr'})
del (log_analysis['ip'])
log_analysis = pd.merge(left = log_analysis, right = sysdb[['ip','c','l','info','ip_cidr']], how = 'left',left_on='dst', right_on='ip')
log_analysis = log_analysis.rename(columns={'c': 'dst_c', 'l': 'dst_l', 'info': 'dst_info','ip_cidr': 'dst_ip_cidr'})
del (log_analysis['ip'])
log_analysis.replace(np.NAN,'-',inplace = True)
log_analysis.sort_values('connects', ascending = False,inplace=True)
dhcp_servers = log_analysis.groupby('dst',as_index=False).agg({'connects':'sum'})
dhcp_servers.sort_values('connects', ascending = False,inplace=True)
dhcp_servers = pd.merge(left = dhcp_servers, right = sysdb[['ip','c','l','info','ip_cidr','vpn_name']], how = 'left',left_on='dst', right_on='ip')
################ get dhcp end #############

################# get voip start ###########
log_voip = log[log['port'].str.contains('_(4060|5050|5061)')]
log_voip.info()
log_voip

log_voip_agg = log_voip.groupby('pair',as_index=False).agg({'connects':'sum'})
log_voip_agg.sort_values('connects', ascending = False,inplace=True)
log_voip_agg

log_voip_agg[['src','dst']] = log_voip_agg.pair.str.split("_",expand=True)
log_analysis = pd.merge(left = log_voip_agg, right = sysdb[['ip','c','l','info','ip_cidr','vpn_name']], how = 'left',left_on='src', right_on='ip')
log_analysis = log_analysis.rename(columns={'c': 'src_c', 'l': 'src_l', 'info': 'src_info','ip_cidr': 'src_ip_cidr'})
del (log_analysis['ip'])
log_analysis = pd.merge(left = log_analysis, right = sysdb[['ip','c','l','info','ip_cidr']], how = 'left',left_on='dst', right_on='ip')
log_analysis = log_analysis.rename(columns={'c': 'dst_c', 'l': 'dst_l', 'info': 'dst_info','ip_cidr': 'dst_ip_cidr'})
del (log_analysis['ip'])
log_analysis.replace(np.NAN,'-',inplace = True)
log_analysis.sort_values('connects', ascending = False,inplace=True)
voip_servers = log_analysis.groupby('dst',as_index=False).agg({'connects':'sum'})
voip_servers.sort_values('connects', ascending = False,inplace=True)
voip_servers = pd.merge(left = voip_servers, right = sysdb[['ip','c','l','info','ip_cidr','vpn_name']], how = 'left',left_on='dst', right_on='ip')
voip_servers

################# get voip end #############



########################### get hostname #############################################################

import os
os.environ['COMPUTERNAME']

########## Auswertung Log-Files python anstelle php #################################################
import os
import pandas as pd
import numpy as np
import glob
from my_functions import *
from datetime import datetime, date, time, timezone, timedelta
import time
import socket
import struct
#from my_functions import *

d = date.today() #- timedelta(0)  #today #today = d.isoformat()
y = date.today() - timedelta(1) #yesterday#yesterday = y.isoformat()

today = d.isoformat()
yesterday = y.isoformat()
#yesterday = '2021-07-14'
#today     = '2021-07-15'

log_files_dir = 'M:\\server_defthw99m5bsrv\\dlw\\projects\\se\\se_cofw_logs\\' + yesterday + '_*.log_export.txt.gz'
log_files = glob.glob(log_files_dir)
#log_files
count=0
for log_file in log_files:
    count = count + 1
    print(str(count).zfill(2) + ': ' +log_file)

startTime = time.time()
count=0
logfile_grey_all = pd.DataFrame(columns=['pair', 'ports'],dtype='str')
for log_file in log_files:
    count = count + 1
    print(str(count).zfill(2) + ': ' +log_file)
    logfile = pd.read_csv(log_file,delimiter=';', usecols=[3,4,5,7,8,10,11,12,13,14,15], dtype ='str',engine = 'c')
    logfile.rename(columns={'Unnamed: 11': 'rule_name'},inplace=True)
    logfile_grey = logfile[logfile['rule_name']=='grey_red2blue']
    logfile_grey['pair'] =  logfile_grey['src'] + ';' + logfile_grey['dst']
    del(logfile_grey['src'])
    del(logfile_grey['dst'])
    logfile_grey['ports'] = logfile_grey['proto']+'_'+logfile_grey['service']+','
    del(logfile_grey['proto'])
    del(logfile_grey['service'])
    logfile_grey = logfile_grey[['pair','ports']]
    logfile_grey_all = pd.concat([logfile_grey_all,logfile_grey],ignore_index=True)

logfile_grey_all.replace(np.NAN,"",inplace=True)
logfile_grey_all
logfile_grey_all['connections'] = 1
#logfile_grey_all[logfile_grey_all['pair'].str.contains('^132.186.60.228')].connections.sum() # scanner Jordanien!
log_group_grey = logfile_grey_all.groupby('pair',as_index=False).agg({'connections':'sum'})
log_group_grey.sort_values('connections',inplace = True, ascending = False)
log_group_grey_top100 = log_group_grey.head(100)
log_group_grey_top100[['src','dst']] = log_group_grey_top100.pair.str.split(";",expand=True,)
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))

#Auswertung welche Ports sind wie oft genutzt
#logfile_grey_all['ports'].value_counts().head(55)
#suche nach targets mit tcp_443,
#server_https = logfile_grey_all[logfile_grey_all['ports']=='tcp_443,']


############# add ports to top100

def get_ports(pair_string):
    logfile_grey_pair = logfile_grey_all[logfile_grey_all['pair'] == pair_string]
    #logfile_grey_pair = logfile_grey_all[logfile_grey_all['pair'].str.contains(pair_string)]
    logfile_grey_pair_ports = logfile_grey_pair[['ports','connections']]
    group_ports = logfile_grey_pair_ports.groupby('ports',as_index=False).agg({'connections':'sum'})
    group_ports.sort_values(by="connections",ascending=False,inplace=True)
    ports_used = group_ports.ports.sum()
    return ports_used
#

#snic['ip_base_bin'] = snic['IP-net-base'].apply(lambda x: ip2int(x))
startTime = time.time()
log_group_grey_top100['ports'] = log_group_grey_top100['pair'].apply(lambda x: get_ports(x))
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))

logfile_grey_all.to_csv('D:\\tmp\\log_file_grey_all.csv_' + yesterday +'.gz',index=None,sep=';')
log_group_grey.to_csv('D:\\tmp\\log_group_grey.csv_' + yesterday +'.gz',index=None,sep=';')
#sysdb_reduced = sysdb[['ip','c','l','info']]
log_group_grey_top100_x = pd.merge(left = log_group_grey_top100, right=sysdb[['ip','c','l','info','ip_cidr']], how='inner', left_on='src', right_on='ip')
del (log_group_grey_top100_x['ip'])
log_group_grey_top100_x = pd.merge(left = log_group_grey_top100_x, right=sysdb[['ip','c','l','info','ip_cidr']], how='inner', left_on='dst', right_on='ip')
log_group_grey_top100_x.rename(columns={'c_x': 'src_c', 'l_x': 'src_l', 'info_x': 'src_info','c_y': 'dst_c', 'l_y': 'dst_l', 'info_y': 'dst_info'},inplace = True)
del (log_group_grey_top100_x['ip_y'])
log_group_grey_top100_x = log_group_grey_top100_x[['src','src_c','src_l','src_info','dst','dst_c','dst_l','dst_info','connections','ports']]
log_group_grey_top100_x.to_csv('d:\\tmp\\log_group_grey_top100_x_'+yesterday+'.csv.gz',sep=';',index = None)


log_group_grey_top100_x.to_clipboard(index = None)

################### Auswertung Log-Files Ende ###########################################

########### find vmware #############################################
vm = logfile_grey_all[logfile_grey_all['ports'].str.contains('p_902,')]
vm[['src','dst']] = vm.pair.str.split(";",expand=True,)
vm

vm_servers = vm.groupby('dst', as_index=False).agg({'connections':'sum'})
vm_servers.sort_values('connections',inplace = True, ascending = False)
vm_servers
#vm = logfile_grey_all[logfile_grey_all['ports'].str.contains('tcp_7938,')]
vm[['src','dst']] = vm.pair.str.split(";",expand=True,)
vm

vm_servers = vm.groupby('dst', as_index=False).agg({'connections':'sum'})
vm_servers.sort_values('connections',inplace = True, ascending = False)
vm_servers


############# Example find Legato Servers ##############
legato = logfile_grey_all[logfile_grey_all['ports'].str.contains('(tcp_7937,|tcp_7938,)')]
legato[['src','dst']] = legato.pair.str.split(";",expand=True,)
legato

legato_servers = legato.groupby('dst', as_index=False).agg({'connections':'sum'})
legato_servers.sort_values('connections',inplace = True, ascending = False)
legato_servers
#legato = logfile_grey_all[logfile_grey_all['ports'].str.contains('tcp_7938,')]
legato[['src','dst']] = legato.pair.str.split(";",expand=True,)
legato

legato_servers = legato.groupby('dst', as_index=False).agg({'connections':'sum'})
legato_servers.sort_values('connections',inplace = True, ascending = False)
legato_servers
############# Example find Legato Servers ##############

############# Example find DHCP Servers ##############
dhcp = logfile_grey_all[logfile_grey_all['ports'].str.contains('(tcp_67,|tcp_68,)')]
#dhcp = logfile_grey_all[logfile_grey_all['ports'].str.contains('tcp_7938,')]
dhcp[['src','dst']] = dhcp.pair.str.split(";",expand=True,)
dhcp

dhcp_servers = dhcp.groupby('dst', as_index=False).agg({'connections':'sum'})
dhcp_servers.sort_values('connections',inplace = True, ascending = False)
dhcp_servers
dhcp_servers['ports'] = logfile_grey_all['pair'].apply(lambda x: get_ports(x))
############# Example find dhcp Servers ##############


############### check ports for one pair ######################


def get_ports(pair_string):
    logfile_grey_pair = logfile_grey_all[logfile_grey_all['pair'] == pair_string]
    #logfile_grey_pair = logfile_grey_all[logfile_grey_all['pair'].str.contains(pair_string)]
    logfile_grey_pair
    logfile_grey_pair_ports = logfile_grey_pair[['ports','connections']]
    logfile_grey_pair_ports
    group_ports = logfile_grey_pair_ports.groupby('ports',as_index=False).agg({'connections':'sum'})
    #group_ports
    group_ports.sort_values(by="connections",ascending=False,inplace=True)
    #group_ports
    ports_used=group_ports.ports.sum()
    return ports_used
#

get_ports('136.157.234.80;10.2.2.20')


# Example for grouping start#
t1 = pd.read_csv('/home/as/t1.csv',sep = '\t')
t2 = pd.read_csv('/home/as/t2.csv',sep = '\t')
t1['pair']=t1['src']+';'+t1['dst']
t2['pair']=t2['src']+';'+t2['dst']
t1g = t1.groupby('pair')['connections'].sum()
t2g = t2.groupby('pair')['connections'].sum()
t1g = t1g.to_frame().reset_index()
t2g = t2g.to_frame().reset_index()
tc = pd.concat([t1g, t2g])
tc = tc.groupby('pair')['connections'].sum()
tc = tc.to_frame().reset_index()
t1p = t1.groupby('pair')['ports'].sum()
t2p = t2.groupby('pair')['ports'].sum()
t1p = t1p.to_frame().reset_index()
t2p = t2p.to_frame().reset_index()
tp = pd.concat([t1p, t2p])
tp = tp.groupby('pair')['ports'].sum()
tp = tp.to_frame().reset_index()
t = pd.merge(left = tc, right = tp)
t['ports'] = t['ports'].str.lower()
t

# Example for grouping end#

import pyperclip


Just like we would when using readcsv, we can pass header=None and names=colnames keyword arguments to read_clipboard in order to fix the problem and supply headers while we’re at it. After copying the csv file above, run the following code:

import pandas as pd

columns = ['ip']
pd.read_clipboard(header=None, names=columns)

################### ad001.siemens.net #############################################
#import pyad
import pyad.adquery
from pyad import aduser
user = aduser.ADUser.from_cn("Scholz Alois oen20323")
user

q = pyad.adquery.ADQuery()

q.execute_query(
    attributes = ["distinguishedName", "description", "managedObjects", "siemens-gid"],
    where_clause = "mail='alois.scholz.ext@siemens.com'",
    base_dn = "DC=ad001, DC=siemens,DC=net"
)


ad_dn = ad_gid = ad_mo =""

for row in q.get_results():
    ad_dn=row["distinguishedName"]
    ad_description=row["description"]
    ad_gid=row["siemens-gid"]
    ad_mo=row["managedObjects"]

ad_dn
ad_gid
ad_mo

################### ad101 #####################################################
import subprocess
cmd = 'd:\\powershell\\ad101.ps1 "(mail=peter.bluschke@siemens-energy.com)"'
completed = subprocess.run(["powershell", "-Command", cmd],capture_output=True,text=True).stdout.strip("\n")
print (completed,sep = '\n')
#




##### ip seek with hostnamed
#hostnames=pd.read_clipboard(header=None,names=['hostname'])
hostnames['hostname'] = hostnames['hostname'].str.lower()
hostnames = hostnames.drop_duplicates(subset=['hostname'])

sysdb['hostname'] = sysdb['hostname'].str.lower()
ip_hostname = pd.merge(left = hostnames, right=sysdb, how='inner', left_on='hostname', right_on='hostname')
ip_hostname['combi'] = ip_hostname['ip'] + ';' + ip_hostname['dns'] 
ip_hostname = ip_hostname.drop_duplicates(subset=['combi'])

ip_hostname.to_clipboard(index = None)

###################### saperion ################################
saperion = pd.read_csv('d:\\tmp\\saperion.csv',sep=';')
saperion = saperion[saperion.dst != 'dst'] #strip other headers

#only targets
targets = ['158.226.216.243','158.226.216.244','158.226.216.247','158.226.216.248','139.16.181.100','139.22.63.170','139.25.231.85']
targets = pd.DataFrame(columns=['dst'],dtype='str',data = targets)
saperion = pd.merge(left = saperion, right = targets) #only dst in targets!
saperion.to_csv('d:\\tmp\\saperion.csv',sep=';',index=None)

#### !!! php analysis with php se_fwloganalyse_ports.php d:\tmp\saperion.csv

saperion_analysis = pd.read_csv('d:\\tmp\\saperion.csv.src-dst.csv',sep=';')



saperion_analysis['pair'] = saperion_analysis['src']+';'+saperion_analysis['dst']
del (saperion_analysis['direction'])
del (saperion_analysis['tcp'])
del (saperion_analysis['udp'])
del (saperion_analysis['icmp'])
del (saperion_analysis['rule'])
del (saperion_analysis['rule_name'])


saperion_analysis_pairs = saperion_analysis.groupby('pair', as_index = False).agg({'connects':'sum'})
saperion_analysis_pairs.sort_values(by="connects",ascending=False,inplace=True)

def get_saperion_ports(pair_string):
    logfile_saperion_pair_ports = saperion_analysis[saperion_analysis['pair'] == pair_string]
    logfile_saperion_pair_ports_list = logfile_saperion_pair_ports[['ports','connects']]
    group_ports = logfile_saperion_pair_ports_list.groupby('ports',as_index=False).agg({'connects':'sum'})
    #group_ports
    group_ports.sort_values(by="connects",ascending=False,inplace=True)
    #group_ports
    ports_used=group_ports.ports.sum()
    return ports_used
#

saperion_analysis_pairs['ports'] = saperion_analysis_pairs['pair'].apply(lambda x: get_saperion_ports(x))

saperion_analysis_pairs[['src','dst']] = saperion_analysis_pairs.pair.str.split(";",expand=True,)
#sysdb_reduced = sysdb[['ip','c','l','info']]
#sysdb_reduced.replace(np.NaN,'-', inplace=True)
saperion_analysis_pairs_x = pd.merge(left = saperion_analysis_pairs, right=sysdb[['ip','c','l','info','ip_cidr']], how='inner', left_on='src', right_on='ip')
saperion_analysis_pairs_x = saperion_analysis_pairs_x.drop_duplicates(subset=['pair'])
del (saperion_analysis_pairs_x['ip'])
saperion_analysis_pairs_x = pd.merge(left = saperion_analysis_pairs_x, right=sysdb[['ip','c','l','info','ip_cidr']], how='inner', left_on='dst', right_on='ip')
saperion_analysis_pairs_x = saperion_analysis_pairs_x.drop_duplicates(subset=['pair'])
del (saperion_analysis_pairs_x['ip'])
saperion_analysis_pairs_x.rename(columns={'c_x': 'src_c', 'l_x': 'src_l', 'info_x': 'src_info','c_y': 'dst_c', 'l_y': 'dst_l', 'info_y': 'dst_info'},inplace = True)
saperion_analysis_pairs_x = saperion_analysis_pairs_x[['src','src_c','src_l','src_info','dst','dst_c','dst_l','dst_info','connects','ports']]
saperion_analysis_pairs_x.to_csv('d:\\tmp\\saperion-info.csv',sep=';',index = None)
#saperion_analysis_pairs.to_clipboard(Index = None)

#################### regex ip ####################
import re

targets = pd.read_excel(r'D:\tmp\Logs_Jun_17__2021_4_22_41_PM_Scan.xlsx')

targets['dst'] = targets['Destination'].apply(lambda x: re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', x).group())
targets_dst = targets['dst'].to_frame('dst')
targets_dst.drop_duplicates(subset=['dst'],inplace=True)


scanner = pd.read_csv(r'D:\tmp\10.224.32.24.csv',sep=';')
scanner = scanner[scanner['num']!='num']
scanner = scanner[scanner['dst']!='10.224.32.24']
scanner['connections']=1
scanner_grouped = scanner.groupby('dst',as_index=False).agg({'connections':'sum'})
scanner_grouped.sort_values(by="connections",ascending=False,inplace=True)
scanner_grouped.connections.sum()
scanner_grouped
#sysdb_reduced = sysdb[['ip','c','l','info']]
scanner_info = pd.merge(left = scanner_grouped, right=sysdb[['ip','c','l','info','ip_cidr']], how='left', left_on='dst', right_on='ip')
scanner_info.replace(np.NaN,'-', inplace=True)
scanner_info = scanner_info[~scanner_info['info'].str.contains('^dc')]
scanner_info = scanner_info[scanner_info['connections']>500]
scanner_info.to_clipboard(index = None)


scanner = pd.read_csv(r'D:\tmp\10.224.48.122.csv',sep=';')
scanner = scanner[scanner['num']!='num']
scanner = scanner[scanner['dst']!='10.224.48.122']
scanner['connections']=1
scanner_grouped = scanner.groupby('dst',as_index=False).agg({'connections':'sum'})
scanner_grouped.sort_values(by="connections",ascending=False,inplace=True)
scanner_grouped.connections.sum()
scanner_grouped
#sysdb_reduced = sysdb[['ip','c','l','info']]
scanner_info = pd.merge(left = scanner_grouped, right=sysdb[['ip','c','l','info','ip_cidr']], how='left', left_on='dst', right_on='ip')
scanner_info.replace(np.NaN,'-', inplace=True)
scanner_info = scanner_info[~scanner_info['info'].str.contains('^dc')]
scanner_info = scanner_info[scanner_info['connections']>500]
scanner_info.to_clipboard(index = None)

#################### seek open ports #############################################################################
import pandas as pd
import socket
def isOpen(ip,port):
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   try:
      s.connect((ip, int(port)))
      s.shutdown(2)
      return True
   except:
      return False

ipl = pd.read_csv(r'd:\python\ip.txt')
ipl['smbstate'] = ipl['ip'].apply(lambda x: isOpen(x,445))

# alternative funktioniert nicht wirklich
import pandas as pd
import socket
async def wait_host_port(host, port, duration=10, delay=2):
    """Repeatedly try if a port on a host is open until duration seconds passed
    
    Parameters
    ----------
    host : str
        host ip address or hostname
    port : int
        port number
    duration : int, optional
        Total duration in seconds to wait, by default 10
    delay : int, optional
        delay in seconds between each try, by default 2
    
    Returns
    -------
    awaitable bool
    """
    tmax = time.time() + duration
    while time.time() < tmax:
        try:
            _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            if delay:
                await asyncio.sleep(delay)
    return False



def get_oldest_merlin_backup():
    files=glob.glob('\\\\defthw99m5bsrv.ad001.siemens.net\\d$\\backup\\merlin\\*-backup.tgz')
    for file in files:
        print(file)
    print (files)
    print('Oldest Merlin Backup File:',files[0])
    return
#
#


################################ SE Zscaler Destinations #######################################
################################ SE Zscaler Destinations #######################################
names = ['dns','ip','port']
#zscaler_log = pd.read_csv(r"D:\compusafe\Kunden\pg\zscaler_logs\se_new.txt.zip",delim_whitespace = True,names = names,dtype = 'str')


zscaler_log = zscaler_log[~zscaler_log['ip'].str.contains('^-------------')]
zscaler_log.replace(np.NaN,'-',inplace = True)
zscaler_log[zscaler_log['port'] == '-']
zscaler_log[zscaler_log['dns'].str.contains('[a-z]',case = False)]
zscaler_log[(zscaler_log['dns'].str.contains('[a-z]',case = False)) & (zscaler_log['port'] == '-')]

zscaler_log = zscaler_log[zscaler_log['dns']!='DestinationHostName']
#zscaler_log['dns'].str.contains('[a-z]',case = False)

def cleanup_zscaler_log_port(ip, port):
    if (port == "-"):
        return str(ip)
    else:
        return str(port)

zscaler_log['port_new'] = zscaler_log.apply(lambda x:cleanup_zscaler_log_port(x['ip'],x['port']), axis = 1)

zscaler_log.to_excel(r"D:\compusafe\Kunden\pg\zscaler_logs\se_new.xlsx",index = None)
#do cosmetic with Excel then get i back
zscaler_log = pd.read_excel(r"D:\compusafe\Kunden\pg\zscaler_logs\se_new.xlsx")


#zscaler_log = zscaler_log[zscaler_log['dns']!='DestinationHostName']

#get lines with no IP but ip in DNS 
#zscaler_log[~zscaler_log['dns'].str.contains('[a-z]',case = False) & ~zscaler_log['ip'].str.contains('\.',case = False)]
#get lines with DNS but no IP
#zscaler_log[zscaler_log['dns'].str.contains('[a-z]',case = False) & ~zscaler_log['ip'].str.contains('\.',case = False)]

#def cleanup_zscaler_log_ip(dns, ip, port):
#    if ((port == "-") & (dns.lower[0] in range('a','z'))):
#        return str('-')
#    else:
#        return str(dns)

#zscaler_log[zscaler_log['ip_new'].str.contains('[a-z]',case = False)]

#zscaler_log['ip_new'] = zscaler_log.apply(lambda x:cleanup_zscaler_log_ip(x['dns'],x['ip'],x['port']), axis = 1)



zscaler_log_x = pd.merge(left=zscaler_log, right=sysdb[['ip','c','l','info','ip_cidr']], on = 'ip',how = 'left')

zscaler_log_x.replace(np.NaN,'-',inplace = True)

zscaler_log_x = zscaler_log_x[zscaler_log_x.ip_cidr.str.contains('/')]
zscaler_ip_cidr_unique = zscaler_log_x.drop_duplicates(subset=['ip_cidr'])

del(zscaler_ip_cidr_unique['dns'])
del(zscaler_ip_cidr_unique['ip'])
del(zscaler_ip_cidr_unique['port'])
del(zscaler_ip_cidr_unique['c'])
del(zscaler_ip_cidr_unique['l'])
del(zscaler_ip_cidr_unique['info'])



#router potential
potential_router = pd.merge(left = zscaler_ip_cidr_unique, right=snic[['IP range/CIDR','potential router ip']], left_on = 'ip_cidr', right_on = 'IP range/CIDR', how = 'left')
del (potential_router['IP range/CIDR'])
zscaler_routing = pd.read_csv(r'D:\tmp\route-check_for_zscaler_potential_routers.txt.csv',sep = ';')
potential_router_x = pd.merge(left = potential_router, right = zscaler_routing, left_on = 'potential router ip', right_on = 'IP', how = 'left')
del (potential_router_x['IP'])
zscaler_log_xx = pd.merge(left = zscaler_log_x, right = potential_router_x, on = 'ip_cidr', how = 'left')


#zscaler_ip_cidr_unique.to_clipboard(index = None)

zscaler_log_vpn = pd.read_excel(r'D:\compusafe\Kunden\darwin\baselining\zscaler_log_vpn.xlsx')
zscaler_log_x_vpn = pd.merge(left = zscaler_log_x, right = zscaler_log_vpn, on = "ip_cidr", how = 'left')
zscaler_log_x_vpn.to_excel(r'D:\compusafe\Kunden\darwin\baselining\zscaler_log_x_vpn.xlsx',index = None)
zscaler_log_x_vpn[zscaler_log_x_vpn['VPN']=='siemens'].shape[0]
zscaler_log_x_vpn.to_excel(r'zscaler_log_x_vpn.xlsx',index = None)

################################ SE Zscaler Destinations End #######################################
################################ SE Zscaler Destinations End #######################################

################################ Darwin/YunexSE Zscaler Destinations Start #####################################
#use prepared with Excel output
zscaler_log = pd.read_excel(r'D:\compusafe\Kunden\darwin\zscaler\yunex_export_analysis_2021-10-09.xlsx')
destination_ip_unique = zscaler_log['DestinationIP'].unique()
destination_ip_unique = pd.DataFrame(zscaler_log['DestinationIP'].unique(),columns=['ip'])
#destination_ip_unique_analysis = pd.merge(left = destination_ip_unique, right = sysdb[['ip','dns','info']], how='left', on='ip')
destination_ip_unique_analysis = pd.merge(left = destination_ip_unique, right = sysdb, how='left', on='ip')
destination_ip_unique_analysis.replace(np.NaN,"", inplace = True)
destination_ip_unique_analysis
destination_ip_unique_analysis.to_clipboard(index = None)


################################ Darwin/YunexSE Zscaler Destinations End #######################################


################################################################################################################################
############################## get greyrule report for one day, replacement of report sources ###################################
################################################################################################################################

# all grey connects
#M:\server_defthw99m5bsrv\dlw\projects\se\se_analysis\se_cofw_logs\2021-07-01.log_report_rules.csv
#D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-07-01.log_report_rules.csv

day_str = '2021-11-05'

log_analysis_dir_se = 'D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\'
rule_report_file = log_analysis_dir_se + day_str + '.log_report_rules.csv'

#D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-07-03.log_report_rules.csv
rule_report = pd.read_csv(rule_report_file,sep=';',dtype = 'str')
rule_report.rename(columns={"dstips": "ip","hits": "connects"},inplace = True)

rule_report.replace(np.NaN,"", inplace = True)

rule_report = rule_report[rule_report['connects'] != '0']
rule_report = rule_report[rule_report['connects'] != 'hits']
rule_report = rule_report[rule_report['connects'] != 'connects']
rule_report["connects"] = rule_report["connects"].astype(str).astype('int64')
rule_report
rule_report[rule_report['rulename']=='blue2red_other'].connects

#rule_report_file_output = 'D:\\tmp\\' + day_str + '.log_report_rules.xlsx'
#rule_report.to_excel(rule_report_file_output, sheet_name='rules',index = None)

rule_report_grey = rule_report[rule_report['rulename'].str.contains('grey')]
#all red to blue connections
all_red2blue_connections = rule_report[rule_report['rulename'] != 'blue2red_other'].connects.sum()

#all grey rule connections
all_grey_rule_connections = rule_report_grey.connects.sum()

#all blue destination ips
all_blue_destination_ips = rule_report[rule_report['rulename']!='blue2red_other'].shape[0]

#All blue destination IPs used via Grey Rule
all_blue_destination_ips_grey = rule_report_grey.shape[0]
#Week Day	Date	cw	All red to blue connections	cw	All Grey Rule Connections	cw	Rational[%]: Grey Rule Connections / All red to blue Connections	cw	All blue destination IPs used	cw	All blue destination IPs used via Grey Rule	cw	Destination IPs used via White Rules	cw	Rational[%]: Destination IPs used via White Rules / All blue destination IPs used	cw	Rational[%]: Destination IPs used via Grey Rule / All blue destination IPs used

all_blue_destination_ips_white = all_blue_destination_ips - all_blue_destination_ips_grey

report_result = ';' + day_str[8:] +'.'+day_str[5:7] + '.' + day_str[0:4] + ';;' + str(all_red2blue_connections) + ';;' + str(all_grey_rule_connections) + ';;'+str(all_grey_rule_connections/all_red2blue_connections).replace('.',',') + ';;' + str(all_blue_destination_ips) + ';;' + str(all_blue_destination_ips_grey) + ';;'+ str(all_blue_destination_ips_white) + ';;' + str(all_blue_destination_ips_white/all_blue_destination_ips).replace('.',',') + ';;'+ str(all_blue_destination_ips_grey/all_blue_destination_ips).replace('.',',')

report_result
#rule_report_grey.replace(" ","", inplace = True)
rule_report_grey = rule_report_grey.replace(' ', '', regex=True)
rule_report_grey_list = rule_report_grey.groupby('ip')
rule_report_grey_list_agg = rule_report_grey_list.aggregate({'connects': np.sum})
rule_report_grey_list_agg.sort_values('connects', ascending = False, inplace = True)
rule_report_grey_list_agg
#index back to ip
rule_report_grey_list_agg = rule_report_grey_list_agg.rename_axis('ip').reset_index()
#enrich with sysdb
rule_report_grey_list_agg_x = pd.merge(left = rule_report_grey_list_agg, right = sysdb[['ip','dns','info']], how='left', on='ip')
#zurück
rule_report_grey_list_agg_x
rule_report_grey_list_agg_x.replace(np.NaN,"-", inplace = True)
rule_report_grey_list_agg_x.to_clipboard(index = None)
#zurück

import subprocess
subprocess.run(['clip.exe'], input=report_result.replace(';','\t').strip().encode('utf-16'), check=True)

################################################################################################################
############################## weekly report generation, with replacement of report sources start ####################
################################################################################################################

log_analysis_dir_se = 'D:\\compusafe\\Kunden\\pg\\00_cofw\\se_analysis\\se_cofw_logs\\'

def get_latest_sysdb():
     files=glob.glob(r'D:\php\sysdb*.gz')
     print('load latest sysdb file: ' + files[-1])
     sysdb = pd.read_csv(files[-1],sep = ';',encoding = "utf-8", dtype = 'str')
     return sysdb
#

#print('date;rules_connects_sum;date;grey_red2blue_targets;date;ratio_in_percent;date;all_red_destination_ips;date;all_grey_destination_ips')
if not 'sysdb' in dir():
    sysdb = get_latest_sysdb()

step = 1
start_day = 7 # before real date today
end_day = 2 # start_day - 7 #before real date today

#start_day = 10
#end_day = 3

i = start_day
while i > end_day:
    d = date.today() - timedelta(i)
    day_str = d.isoformat()
    rule_report_file = log_analysis_dir_se + day_str + '.log_report_rules.csv'
    #D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-07-03.log_report_rules.csv
    rule_report = pd.read_csv(rule_report_file,sep=';', encoding = 'cp1252', dtype = 'str')
    rule_report.rename(columns={"dstips": "ip","hits": "connects"},inplace = True)
    rule_report.replace(np.NaN,"", inplace = True)
    rule_report = rule_report[rule_report['connects'] != '0']
    rule_report = rule_report[rule_report['connects'] != 'connects']
    rule_report = rule_report[rule_report['connects'] != 'hits']
    rule_report["connects"] = rule_report["connects"].astype(str).astype('int64')
#    rule_report_grey = rule_report[rule_report['rulename'].str.contains('grey')]
    rule_report_grey = rule_report[rule_report['rulename'].str.contains('^grey_red2blue')]
    #rule_report_grey
    if i == start_day:
        week_log = rule_report_grey
    else:
        week_log = pd.concat([week_log,rule_report_grey],ignore_index=True)
    # report generation lines
    all_red2blue_connections = rule_report[rule_report['rulename']!='blue2red_other'].connects.sum()
    #all_red2blue_connections
    #all grey rule connections
    all_grey_rule_connections = rule_report_grey.connects.sum()
    #all_grey_rule_connections
    #all blue destination ips
    all_blue_destination_ips = rule_report[rule_report['rulename']!='blue2red_other'].shape[0]
    #all_blue_destination_ips
    #All blue destination IPs used via Grey Rule
    all_blue_destination_ips_grey = rule_report_grey.shape[0]
    #all_blue_destination_ips_grey
    #Week Day	Date	cw	All red to blue connections	cw	All Grey Rule Connections	cw	Rational[%]: Grey Rule Connections / All red to blue Connections	cw	All blue destination IPs used	cw	All blue destination IPs used via Grey Rule	cw	Destination IPs used via White Rules	cw	Rational[%]: Destination IPs used via White Rules / All blue destination IPs used	cw	Rational[%]: Destination IPs used via Grey Rule / All blue destination IPs used
    all_blue_destination_ips_white = all_blue_destination_ips - all_blue_destination_ips_grey
    #all_blue_destination_ips_white
    report_result = ';' + day_str[8:] +'.'+day_str[5:7] + '.' + day_str[0:4] + ';;' + str(all_red2blue_connections) + ';;' + str(all_grey_rule_connections) + ';;'+str(all_grey_rule_connections/all_red2blue_connections).replace('.',',') + ';;' + str(all_blue_destination_ips) + ';;' + str(all_blue_destination_ips_grey) + ';;'+ str(all_blue_destination_ips_white) + ';;' + str(all_blue_destination_ips_white/all_blue_destination_ips).replace('.',',') + ';;'+ str(all_blue_destination_ips_grey/all_blue_destination_ips).replace('.',',')
    report_result
    
    i = i - step

#### top10 generation
week_log_reduced = week_log[['ip','connects']]
week_log_reduced['ip'] = week_log_reduced['ip'].str.strip()

dst_list = week_log_reduced.groupby('ip')
dst_list_agg = dst_list.aggregate({'connects': np.sum})
dst_list_agg.sort_values('connects', ascending = False, inplace = True)

dst_list_agg = dst_list_agg/(start_day-end_day) #division by days
dst_list_agg['connects'] = dst_list_agg['connects'].astype('int64')
dst_list_agg_index = dst_list_agg.reset_index()
dst_list_agg_index_x = pd.merge(left = dst_list_agg_index, right = sysdb, how = 'left', on='ip')

dst_top_100_x = dst_list_agg_index_x.head(100)

dst_top_100_x.head(55)[['connects','ip','dns','c','l','info']]

#today = '2021-11-01'
dst_top_100_x.head(10)[['connects','ip','dns','c','l','info']].to_csv('D:\\compusafe\\Kunden\\pg\\00_cofw\\performance_logs\\grey_rule_weekly_top10_dst_'+today+'.csv', sep = ';', encoding = 'cp1252',index=None)

################################################################################################################
############################## weekly report generation, with replacement of report sources end ################
################################################################################################################



# suche ad005 domain controller
sysdb[sysdb['info'].str.contains('^dc',case = False) & sysdb['dns'].str.contains('.ad005.',case = False)]

# suche ad101 domain controller
sysdb[sysdb['info'].str.contains('^dc',case = False) & sysdb['dns'].str.contains('.ad101.',case = False)]


all_red_networks_express = pd.read_excel(r'D:\tmp\all_red_networks_express.xlsx')
all_red_networks_se = pd.read_excel(r'D:\tmp\all_red_networks_se.xlsx')
ipman

########## Auswertung tsa36 #################################################
import os
import pandas as pd
import numpy as np
import glob
from my_functions import *
from datetime import datetime, date, time, timezone, timedelta
import time
import socket
import struct
#from my_functions import *

d = date.today() #- timedelta(0)  #today #today = d.isoformat()
y = date.today() - timedelta(1) #yesterday#yesterday = y.isoformat()

today = d.isoformat()
#yesterday = y.isoformat()
#yesterday = '2021-07-14'
#today     = '2021-07-15'
day_str = '2021-07-26'
#tsa36 = pd.read_excel(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\applications\Apps_with_TSA_36_Andre_2021-07-14.xlsx')
#tsa36 = pd.read_clipboard()

log_files_dir = 'M:\\server_defthw99m5bsrv\\dlw\\projects\\se\\se_cofw_logs\\' + day_str + '_*.log_export.txt.gz'
log_files = glob.glob(log_files_dir)
#log_files
count=0
for log_file in log_files:
    count = count + 1
    print(str(count).zfill(2) + ': ' +log_file)

startTime = time.time()
count=0
#logfile_grey_all = pd.DataFrame(columns=['pair', 'ports'],dtype='str')
for log_file in log_files:
    count = count + 1
    print(str(count).zfill(2) + ': ' +log_file)
    logfile = pd.read_csv(log_files[count],delimiter=';', usecols=[3,4,5,7,8,10,11,12,13,14,15], dtype ='str',engine = 'c')
    logfile.rename(columns={'Unnamed: 11': 'rule_name'},inplace=True)
    logfile = logfile[logfile['action'] == 'accept']
    #logfile_tsa36 = pd.merge(left = logfile, right = tsa36, left_on = 'dst', right_on = 'ip',  how = 'inner')
    logfile_tsa36 = pd.merge(left = logfile, right = tsa36[['Ips']], left_on = 'dst', right_on = 'Ips',  how = 'inner') #filter log on tsa36 ips
    del (logfile_tsa36['Ips']) # filter not needed anymore
    logfile_tsa36['pair'] =  logfile_tsa36['src'] + ';' + logfile_tsa36['dst']
    #del(logfile_tsa36['src'])
    #del(logfile_tsa36['dst'])
    logfile_tsa36['ports'] = logfile_tsa36['proto']+'_'+logfile_tsa36['service']+','
    del(logfile_tsa36['proto'])
    del(logfile_tsa36['service'])
    if count == 1:
        logfile_tsa36_all = logfile_tsa36
    else:
        logfile_tsa36_all = pd.concat([logfile_tsa36_all,logfile_tsa36],ignore_index=True)
    #

executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))

######### Schleife Ende #######

logfile_tsa36_all.replace(np.NAN,"",inplace=True)
logfile_tsa36_all
logfile_tsa36_all['connections'] = 1

tsa36_all_migrated2red = logfile_tsa36_all[logfile_tsa36_all['rule_name'] == 'blue2red_other']
tsa36_destination_ips_red = len(tsa36_all_migrated2red['dst'].unique())

tsa36_all_blue = logfile_tsa36_all[logfile_tsa36_all['rule_name'] != 'blue2red_other']
tsa36_destination_ips_blue = len(tsa36_all_blue['dst'].unique())

#eindampfen
#logfile_tsa36_all[logfile_tsa36_all['pair'].str.contains('^132.186.60.228')].connections.sum() # scanner Jordanien!
log_group_tsa36_blue = tsa36_all_blue.groupby('pair',as_index=False).agg({'connections':'sum'})
log_group_tsa36_blue.sort_values('connections',inplace = True, ascending = False)
log_group_tsa36_blue[['src','dst']] = log_group_tsa36_blue.pair.str.split(";",expand=True)

log_group_tsa36_blue = pd.merge(left = log_group_tsa36_blue, right = tsa36 , left_on = 'dst', right_on = 'Ips', how = 'left')
del (log_group_tsa36_blue['Ips'])
sysdb_reduced = sysdb[['ip','c','l','info']]

log_group_tsa36_blue = log_group_tsa36_blue.rename(columns={c:c.strip().lower() for c in log_group_tsa36_blue.columns}) #clean titels

log_group_tsa36_blue_x = pd.merge(left = log_group_tsa36_blue, right = sysdb_reduced, left_on = 'src', right_on = 'ip', how = 'left')
log_group_tsa36_blue_x = pd.merge(left = log_group_tsa36_blue_x, right = sysdb_reduced, left_on = 'dst', right_on = 'ip', how = 'left')
log_group_tsa36_blue_x.rename(columns={'c_x': 'src_c', 'l_x': 'src_l', 'info_x': 'src_info','c_y': 'dst_c', 'l_y': 'dst_l', 'info_y': 'dst_info'},inplace = True)
del (log_group_tsa36_blue_x['ip_x'])
del (log_group_tsa36_blue_x['ip_y'])
log_group_tsa36_blue_x
tsa36_output_filename = 'D:\\tmp\\tsa36_log_analysis_' + day_str + '.xlsx'
tsa36_output_sheetname = 'tsa_36_' + day_str
log_group_tsa36_blue_x.to_excel(tsa36_output_filename, index = None, sheet_name = tsa36_output_sheetname)
# report
tsa36_report_no_ips = len(tsa36) #Number of IPs in TSA36 list

################# ende #############################


log_group_tsa36_top100 = log_group_tsa36.head(100)
log_group_tsa36_top100[['src','dst']] = log_group_tsa36_top100.pair.str.split(";",expand=True,)

################# multiple ip to one ip ##################
import re
inputfile = 'D:\\tmp\\ITAM_Linux_Server_Suse_2021-08-10.xlsx'
outputfile = open(inputfile + '.csv', "w")
outputfile.write('ip;DNS;c;l;hostname;domain;gid;mail;os\n')

linux_server = pd.read_excel(r'D:\tmp\ITAM_Linux_Server_Suse_2021-08-10.xlsx')

#for index, row in linux_server.iterrows():
#    print(row['IP Addresses.ip'], ";",row['FQDN'])
#
#for row in linux_server.iterrows():
#   print (str(row['IP Addresses.ip']) + ";" + str(row['FQDN']))

for index, row in linux_server.iterrows():
    ipstr = row['IP Addresses.ip']
    ips = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',str(ipstr))
    if len(ips)>0:
        for ip in ips:
            outputstr = ip +";"+row["FQDN"]+";"+row["Country"]+";"+row["Location"]+";"+row["Hostname"]+";"+row["AD Domain"]+";"+row["Owner Contact.id"]+";"+row["Owner Contact.email"]+";"+row["Operating System"]
            print(outputstr)
            outputfile.write(outputstr+'\n')
#

outputfile.close()


text = '139.25.228.137; 194.138.20.69; 139.25.228.137; 194.138.20.69'
#re.findall(r'([0-2][0-5]{2}|\d{2}|\d).([0-2][0-5]{2}|\d{2}|\d).([0-2][0-5]{2}|\d{2}|\d).([0-2][0-5]{2}|\d{2}|\d)', text)
ips = re.fullmatch('([0-2][0-5]{2}|\d{2}|\d).([0-2][0-5]{2}|\d{2}|\d).([0-2][0-5]{2}|\d{2}|\d).([0-2][0-5]{2}|\d{2}|\d)', text)
#find if ip valid
import re
IPV4 = re.fullmatch('([0-2][0-5]{2}|\d{2}|\d).([0-2][0-5]{2}|\d{2}|\d).([0-2][0-5]{2}|\d{2}|\d).([0-2][0-5]{2}|\d{2}|\d)', '100.1.1.2')

if IPV4:
    print ("Valid IP address")
else:
    print("Invalid IP address")
#
re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',text)

################################# COFW Policy all_red_networks checks ##################################################


# SE Policy Building calculate missing IP Ranges from IP Management in "all_red_networks"
#get latest snic-db, add binary values
snicfiles=glob.glob(r'D:\snic\*-snic_ip_network_assignments.csv')
print('load latest SNIC file: ' + snicfiles[-1])
snic = pd.read_csv(snicfiles[-1],sep = ';',encoding = "latin-1", dtype = 'str')
snic['ip_base_bin'] = snic['IP-net-base'].apply(lambda x: ip2int(x))
snic['ip_top_bin'] = snic['IP-net-top'].apply(lambda x: ip2int(x))

'''#get latest ipman table from d:\tmp\ipnet.csv
ipman = pd.read_csv(r'D:\tmp\ipnet.csv',delimiter=';', encoding='cp1252' )
ipman = ipman.replace('&sect;','&')
ipman['ip_base_bin'] = ipman['ip_net_base'].apply(lambda x: ip2int(x))
ipman['ip_top_bin'] = ipman['ip_net_top'].apply(lambda x: ip2int(x))
'''

policy_name = r'D:\compusafe\Kunden\pg\00_cofw\policies\2022-02-01_se_ruleset_v086_raw_from_done_ASC.xlsx'
sheet_red = 'all_red_networks'
all_red = pd.read_excel(policy_name,sheet_name = sheet_red, encoding = 'cp1252', dtype = 'str', na_values=['-'], usecols="A,K:L,P:S,AA,AT,AR")
all_red.replace(np.NAN,"",inplace=True)
all_red = all_red[(all_red['action'] != 'deleted')]
all_red

sheet_blue = 'SE_RFC_exceptions_in_blue'
all_blue = pd.read_excel(policy_name,sheet_name = sheet_blue, encoding = 'cp1252', dtype = 'str', na_values=['-'], usecols="A,K:L,P:S,AA,AT,AR")
all_blue.replace(np.NAN,"",inplace=True)
all_blue = all_blue[all_blue['Routing Exception'] != 'deleted']
all_blue


#pd.merge(left = all_red, right=ipman, how='left', left_on='IPrange/CIDR', right_on='ip_cidr')
#pd.merge(left = all_red, right=all_blue, how='left', left_on='IPrange/CIDR', right_on='IPrange/CIDR')
#check_red_ip_ranges_in_blue = pd.join(left = all_blue, right = all_red, how = 'left', on = 'IP-net-base')
check_red_ip_ranges_in_blue = pd.merge(left = all_blue, right = all_red, how = 'inner', on = 'IP-net-base')
check_red_ip_ranges_in_blue
check_blue_ip_ranges_in_red = pd.merge(left = all_red, right = all_blue, how = 'inner', on = 'IP-net-base')
check_blue_ip_ranges_in_red

#r'snic_ip_network_assignments_se.csv'
snic_se = pd.read_csv(r'D:\snic\snic_ip_network_assignments_se.csv',delimiter=';', encoding='cp1252',dtype ='str' )
#snic_se.to_excel(r'D:\snic\snic_ip_network_assignments_se.xlsx',encoding='cp1252',index = None)

missing_snic_se_ip_ranges_in_all_red = pd.merge(left = snic_se, right = all_red, on = 'IP-net-base', how = 'outer') 
missing_snic_se_ip_ranges_in_all_red

missing_snic_se_ip_ranges_in_all_red = pd.concat([snic_se,all_red]).drop_duplicates(keep=False)
snic_se.compare(all_red)

pd.concat([df1, df2]).loc[df1.index.symmetric_difference(df2.index)]
pd.concat([snic_se, all_red]).loc[snic_se.index.symmetric_difference(all_red.index)]
pd.concat([all_red, snic_se]).loc[all_red.index.symmetric_difference(snic_se.index)]

np.where(all_red != snic_se)
all_red.compare(all_se, align_axis=0)
all_red.merge(snic_se,indicator = True, how='left').loc[lambda x : x['_merge']!='both']
snic_se. merge(all_red, how = 'outer' ,indicator=True). loc[lambda x : x['_merge']=='left_only']

check_missing_ipman_ip_ranges_in_all_red = pd.merge(left = ipman, right = all_red, how = 'left', left_on = 'ip_net_base',right_on = 'IP-net-base')
check_missing_ipman_ip_ranges_in_all_red
missing_ipman_ip_ranges_in_all_red = check_missing_ipman_ip_ranges_in_all_red[check_missing_ipman_ip_ranges_in_all_red['IP-net-base'].isnull()]
missing_ipman_ip_ranges_in_all_red = missing_ipman_ip_ranges_in_all_red[~missing_ipman_ip_ranges_in_all_red['snic_vpn_name'].isnull()]
pd.merge(left = ipman, right = all_red, how = 'left', left_on = 'ip_net_base',right_on = 'IP-net-base')
missing_ipman_ip_ranges_in_all_red
missing_ipman_ip_ranges_in_all_red.replace(np.NaN,"", inplace = True)
#missing ip ranges without blue ip ranges
missing_ipman_ip_ranges_in_all_red = missing_ipman_ip_ranges_in_all_red[~missing_ipman_ip_ranges_in_all_red['net_address'].isin(all_blue['IP range/CIDR'])]
missing_ipman_ip_ranges_in_all_red_with_snic_entry = pd.merge(left = snic, right = missing_ipman_ip_ranges_in_all_red, how = 'inner', left_on = 'IP range/CIDR', right_on = 'net_address')
missing_ipman_ip_ranges_in_all_red_with_snic_entry

ip_ranges_to_be_deleted = pd.merge(left = all_red, right = snic, how = 'left', left_on = 'IP-net-base' , right_on = 'IP-net-base')
ip_ranges_to_be_deleted = ip_ranges_to_be_deleted[ip_ranges_to_be_deleted['potential router ip'].isnull()]
ip_ranges_to_be_deleted
ip_ranges_to_be_deleted['IP-net-base'].to_clipboard(header = None, index = None)
#snic()
#zurück2

######################################################################################
############### get blue ips for n days ##############################################
######################################################################################
import os.path
import time
step = 1
start_day = 91 # before real date today
#start_day = 1 # only one day
end_day = 0 # start_day - 7 #before real date today

i = start_day
while i > end_day:
    d = date.today() - timedelta(i)
    day_str = d.isoformat()
    ip_unique_daily_file = log_analysis_dir_se + day_str + '.log_export_blue.txt.src-dst.csv.unique.ips.csv.gz'
    print(ip_unique_daily_file)
    if os.path.exists(ip_unique_daily_file):
        ip_unique_daily = pd.read_csv(ip_unique_daily_file,sep=';', usecols=[0,2], encoding = 'cp1252', dtype = 'str')
        ip_unique_daily.rename(columns={'IP': 'ip','Info': 'connects'},inplace=True) ###zurück
        ip_unique_daily.replace(np.NaN,"", inplace = True)
        ip_unique_daily["connects"] = ip_unique_daily["connects"].astype(str).astype('int64')
        if i == start_day:
            all_blue_src_ips = ip_unique_daily
        else:
            all_blue_src_ips = pd.concat([all_blue_src_ips,ip_unique_daily],ignore_index=True)
    i = i - step

#
all_blue_src_ips
blue_src_list = all_blue_src_ips.groupby('ip')
blue_src_list_agg = blue_src_list.aggregate({'connects': np.sum})
blue_src_list_agg.sort_values('connects', ascending = False, inplace = True)
blue_src_list_agg_index = blue_src_list_agg.reset_index()
blue_src_list_agg_index_x = pd.merge(left=blue_src_list_agg_index, right=sysdb[['ip','c','l','info']], how='left', on='ip')

########################################## get itam import by json files #########################################################
########################################## get itam import by json files #########################################################
import pandas as pd
import numpy as np
import time
import glob
startTime = time.time()
itam_jason_files = glob.glob(r'D:\compusafe\Kunden\pg\baselining\itam\2021-09-17-itamdump-*.json')
first_write = True

for itam_jason_file in itam_jason_files:
    print(itam_jason_file)
    itam_part = pd.read_json(itam_jason_file, lines = True)
    if (first_write == True):
        itam = itam_part
        first_write = False
    else:
        itam = pd.concat([itam,itam_part], ignore_index = True)
    print(str(itam_jason_file) + ': ' + str(itam.shape[0]))

executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))
itam
#itam.to_csv(r'D:\compusafe\Kunden\pg\baselining\itam\2021-09-17-itam.csv.gz', index = False)
########################################## get itam import by json files end #########################################################
########################################## get itam import by json files end #########################################################


########################################## get itam import by one json file #########################################################
########################################## get itam import by one json file #########################################################

import pandas as pd
import numpy as np
import time
startTime = time.time()
itam = pd.read_json(r'D:\compusafe\Kunden\pg\baselining\itam\2021-09-17-itamdump_total.json.gz', lines = True)
itam.replace(np.NaN,"None", inplace = True)
del (itam['MAC Addresses'])
del (itam['Deactivation Date'])
del (itam['Last Scan'])
del (itam['MMSA Contract'])
del (itam['System ID'])
del (itam['Provider'])
del (itam['Remediation Contacts'])
del (itam['Data Timestamp'])
del (itam['Inconsitent Reasons'])
del (itam['Brown Network'])
del (itam['Contract Type'])
del (itam['Landscape ID'])
del (itam['Other Contacts'])
del (itam['AD Identifier'])
del (itam['Disaster Recovery'])
del (itam['System Administrators'])
del (itam['Critical'])
del (itam['Agents'])
del (itam['Provider ID'])
del (itam['Maint Window'])
del (itam['Backup Policy'])
del (itam['System State'])
del (itam['Is Infra'])
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))
# expand Owner data to columns
itam = (
    itam["Owner Contact"]
    .apply(pd.Series)
    .merge(itam, left_index=True, right_index = True)
)
del (itam['firstname'])
del (itam['idSource'])
del (itam['lastname'])
del (itam['role'])
del (itam['Owner Contact'])
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))
#del (itam[0])
#itam.to_csv(r'D:\compusafe\Kunden\pg\baselining\itam\2021-09-17-itam.csv.gz', index = False)
#              D:\compusafe\Kunden\pg\baselining\itam\2021-09-17-itam.csv.gz
itam_server_se =  itam[(itam['Unit']=='SE') & (itam['System Type']=='Server')]

s = itam_server_se['IP Addresses'].apply(pd.Series).add_prefix('ip.')
s = s['ip.0']
itam_server_se_ip = pd.concat([itam_server_se.drop(['IP Addresses'], axis=1), s], axis=1)#.set_index('id')

itam_server_se_ip_x = (
    itam_server_se_ip["ip.0"]
    .apply(pd.Series)
    .merge(itam_server_se_ip, left_index=True, right_index = True)
)
del (itam_server_se_ip_x[0])
del (itam_server_se_ip_x['main'])
del (itam_server_se_ip_x['networkid'])
del (itam_server_se_ip_x['routingdomains'])
del (itam_server_se_ip_x['iptype'])
del (itam_server_se_ip_x['ip.0'])



itam[(itam['Unit']=='SE') & (itam['System Type']=='Server')]
itam[(itam['Unit']=='SE') & True]['System Type'].unique()
itam['System Type'].unique() #-------> array(['Server', 'Client', 'Unknown', 'Network'], dtype=object)

itam[['IP Addresses','FQDN','Country','Location','System Type','Owner Contact','Operating System','Unit']]

########################################## get itam import by one json file end #########################################################
########################################## get itam import by one json file end #########################################################

############ JSON Normalize Tests ###################
# load data using Python JSON module
import pandas as pd
import numpy as np
import time
import json
with open(r'D:\compusafe\Kunden\pg\baselining\itam\test.json','r') as f:
    data = json.loads(f.read())

dataj = pd.read_json(r'D:\compusafe\Kunden\pg\baselining\itam\test.json', lines = True)
result = pd.json_normalize(dataj['Owner'])

with open(r'D:\compusafe\Kunden\pg\baselining\itam\test.json','r') as f:
    data = [json.loads(line) for line in f]
pd.json_normalize(data)

import json
# load data using Python JSON module
with open('data/simple.json','r') as f:
    data = json.loads(f.read())
    
# Flattening JSON data
pd.json_normalize(data)


#
# Normalizing data
multiple_level_data = pd.json_normalize(data, record_path =['Results'], meta =['original_number_of_clusters','Scaler','family_min_samples_percentage'], meta_prefix='config_params_', record_prefix='dbscan_')
# Saving to CSV format
multiple_level_data.to_csv('multiplelevel_normalized_data.csv', index=False)


############# zurück

dataj = pd.read_json(r'D:\compusafe\Kunden\pg\baselining\itam\test.json', lines = True)

# expand Owner data to columns
datajxo = (
    dataj["Owner Contact"]
    .apply(pd.Series)
    .merge(dataj, left_index=True, right_index = True)
)
del (datajxo['firstname'])
del (datajxo['idSource'])
del (datajxo['lastname'])
del (datajxo['role'])

del (datajxo['MAC Addresses'])
del (datajxo['Deactivation Date'])
del (datajxo['Last Scan'])
del (datajxo['MMSA Contract'])
del (datajxo['System ID'])
del (datajxo['Provider'])
del (datajxo['Remediation Contacts'])
del (datajxo['Data Timestamp'])
del (datajxo['Inconsitent Reasons'])
del (datajxo['Brown Network'])
del (datajxo['Contract Type'])
del (datajxo['Landscape ID'])
del (datajxo['Other Contacts'])
del (datajxo['AD Identifier'])
del (datajxo['Disaster Recovery'])
del (datajxo['System Administrators'])
del (datajxo['Critical'])
del (datajxo['Agents'])
del (datajxo['Provider ID'])
del (datajxo['Maint Window'])
del (datajxo['Backup Policy'])
del (datajxo['Owner Contact'])
del (datajxo['System State'])
del (datajxo['Is Infra'])

datajxo

s = datajxo['IP Addresses'].apply(pd.Series).add_prefix('ip.')
s = s['ip.0']
datajxoip = pd.concat([datajxo.drop(['IP Addresses'], axis=1), s], axis=1)#.set_index('id')

datajxoip2 = (
    datajxoip["ip.0"]
    .apply(pd.Series)
    .merge(datajxoip, left_index=True, right_index = True)
)
del (datajxoip2[0])
del (datajxoip2['main'])
del (datajxoip2['networkid'])
del (datajxoip2['routingdomains'])
del (datajxoip2['ip.0'])


datajxoip2 = pd.json_normalize(datajxoip,record_path = ['ip.0'], meta =['networkid','ip','main','iptype','routingdomains'], meta_prefix='ip_params_', errors = 'ignore' )

df=pd.json_normalize(datajxoip,record_path = ['IP Addresses'],meta =['networkid','ip','main','iptype','routingdomains'], meta_prefix='ip_params_',errors = 'ignore' )


#multiple_level_data = pd.json_normalize(datajxo, record_path =['IP Addresses'], meta =['networkid','ip','main','iptype','routingdomains'], meta_prefix='ip_params_', record_prefix='dbscan_')
multiple_level_data = pd.json_normalize(datajxo, record_path =['IP Addresses'], meta =['networkid','ip','main','iptype','routingdomains'], meta_prefix='ip_params_', record_prefix='dbscan_', errors='ignore')

# Extract the issue type name to a new column called "issue_type"
df_issue_type = (
    df["issuetype"]
    .apply(pd.Series)
    .rename(columns={"name": "issue_type_name"})["issue_type_name"]
)
df = df.assign(issue_type_name = df_issue_type)



orient="records"
.json_normalize string indices must be integers
df=pd.json_normalize(datajxo['IP Adresses'],max_level=1,orient="records")

df=pd.json_normalize(datajxo,record_path =['IP Adresses'],meta=['networkid','ip'])

#[{'networkid': 11415, 'ip': '139.23.77.217', 'main': 0, 'iptype': 'Dynamic', 'routingdomains': 1}]
#[{'networkid': 10555, 'ip': '167.87.38.212', 'main': 0, 'iptype': 'Dynamic', 'routingdomains': 1}, {'networkid': 10555, 'ip': '139.22.34.198', 'main': 0, 'iptype': 'Dynamic', 'routingdomains': 1}, {'networkid': 23914, 'ip': '139.22.34.198', 'main': 0, 'iptype': 'Dynamic', 'routingdomains': 1}, {'networkid': 23914, 'ip': '167.87.38.212', 'main': 0, 'iptype': 'Dynamic', 'routingdomains': 1}]
#meta=['cod',['city','country'],['city','name'],['city','id'],['city','coord','lat'],['city','coord','lon']]

dataj = (
    dataj["IP Addresses"]
    .apply(pd.Series)
    .merge(dataj, left_index=True, right_index = True)
)


######################## express analyse #####################


######################## sppal analyse #####################

sppal = pd.read_csv(r'D:\compusafe\Kunden\IC_MOL_LAS_Goliath_David\Firewall\analysis\firewall_logs\2021-10-04.log_export.txt.src-dst.csv.gz',sep = ';')
sppal.replace(np.NaN,"-", inplace = True)
#sppal[sppal['ports'].str.contains('_53,')].to_clipboard(index = None)
sppal.sort_values('connects',inplace = True,ascending=False)
sppal = pd.merge(left = sppal, right=sysdb[['ip','c','l','info']], how='left', left_on='src', right_on='ip')
del (sppal['ip'])
sppal = sppal.rename(columns={"c": "src_c", "l": "src_l", "info": "src_info"})
sppal = pd.merge(left = sppal, right=sysdb[['ip','c','l','info']], how='left', left_on='dst', right_on='ip')
del (sppal['ip'])
sppal = sppal.rename(columns={"c": "dst_c", "l": "dst_l", "info": "dst_info"})
sppal.replace(np.NaN,"-", inplace = True)


sppal.to_excel(r'D:\compusafe\Kunden\IC_MOL_LAS_Goliath_David\Firewall\analysis\firewall_logs\2021-10-04.log_export.txt.src-dst.xlsx',index = None)
#sppal_dns = sppal[sppal['ports'].str.contains('_53,')]
#sppal_dns_without_src_dc = sppal_dns[~sppal_dns['src_info'].str.contains('^dc')]
#sppal_dns_without_src_dc
sppal_src_scans = sppal['src'].value_counts()
sppal_src_scans_df = sppal_src_scans.reset_index()
sppal_src_scans_df = sppal_src_scans_df.rename(columns = {'src': 'frequency','index': 'src' })
sppal_src_scans_df
sppal[sppal['src'] == '163.242.6.163']
sppal[sppal['src'] == '163.242.6.163']['connects'].sum()

############################ sppal analyse end ####################

############################ project_log analyse start ####################

project_log = pd.read_csv(r'D:\compusafe\Kunden\mobility\00_firewall_cofw\analysis\2021-09-29.log_export_red.txt.src-dst.csv.gz',sep = ';',dtype = 'str')
project_log = pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-10-07.log_export_red.txt.src-dst.csv.gz',sep = ';',dtype = 'str')
project_log = pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-11-02.log_export_red.txt.src-dst.csv.gz',sep = ';')
project_log = pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-11-05.log_export_red.txt.src-dst.csv.gz',sep = ';')
project_log = pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-11-20.log_export_red.txt.src-dst.csv.gz',sep = ';')
project_log.replace(np.NaN,"-", inplace = True)
project_log = project_log[project_log['rule_name'].str.contains('^grey_black2blue')] #<<<<<< Filter^a log File for special searchings
#.to_clipboard(index = None)
project_log.sort_values('connects',inplace = True,ascending=False)
project_log = pd.merge(left = project_log, right=sysdb[['ip','c','l','info']], how='left', left_on='src', right_on='ip')
del (project_log['ip'])
project_log = project_log.rename(columns={"c": "src_c", "l": "src_l", "info": "src_info"})
project_log = pd.merge(left = project_log, right=sysdb[['ip','c','l','info']], how='left', left_on='dst', right_on='ip')
del (project_log['ip'])
project_log = project_log.rename(columns={"c": "dst_c", "l": "dst_l", "info": "dst_info"})
project_log.replace(np.NaN,"-", inplace = True)
project_log
startTime = time.time()
project_log['category']=project_log[['src','src_info','dst','dst_info','ports']].apply(lambda x: autoanalysis(x['src'],x['src_info'],x['dst'],x['dst_info'],x['ports']),axis=1)
executionTime = (time.time() - startTime)
print('Execution time in seconds: ' + str(executionTime))

del(project_log['tcp'])
del(project_log['udp'])
del(project_log['icmp'])
del(project_log['rule'])
del(project_log['icmp'])
del(project_log['accepted'])
project_log

#project_log.to_excel(r'd:\tmp\grey_black2red.xlsx',index = 'None')
#find SAP traffic
#project_log[(project_log['category']=='sap') & (project_log['rule_name'].str.contains('grey_red2blue'))]


#project_log['category'].value_counts()
#project_log['src_l'].value_counts()
#project_log['dst_l'].value_counts()
#project_log.memory_usage(deep=False)
#project_log.memory_usage(deep=True)
#project_log.to_excel(r'd:\tmp\se_dns_analysis_2021-10-07.xlsx',sheet_name = 'dns_connections',columns = ['src','src_c','src_l','src_info','dst','dst_c','dst_l','dst_info','ports','direction','connects','orig'],index = None)

# display large dataframes in an html iframe
def ldf_display(df, lines=500):
    txt = ("<iframe " +
           "srcdoc='" + df.head(lines).to_html() + "' " +
           "width=1000 height=500>" +
           "</iframe>")

    return IPython.display.HTML(txt)

#

#zurück3



# check frequency of certain requests
#project_dns = project[project['ports'].str.contains('_53,')]
#project_dns_without_src_dc = project_dns[~project_dns['src_info'].str.contains('^dc')]
#project_dns_without_src_dc
project_src_scans = project['src'].value_counts()
project_src_scans_df = project_src_scans.reset_index()
project_src_scans_df = project_src_scans_df.rename(columns = {'src': 'frequency','index': 'src' })
project_src_scans_df
project[project['src'] == '163.242.6.163']
project[project['src'] == '163.242.6.163']['connects'].sum()

############################ project_log analyse end ####################

D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2021-10-10.log_export_red.txt.src-dst.csv.gz

############################ scd analysis for shs start ###################

scd_file = r'D:\compusafe\Kunden\shs\baselining\scd_shs_2021-10-04.csv'
scd = pd.read_csv(scd_file, sep = ';', encoding = 'cp1252', dtype = 'str')
scd.replace(np.NaN,"-", inplace = True)
shs = scd[scd['department'].str.contains('^SHS',case = False)]


shs['internal'] = shs['userType'].apply(lambda x: 1 if x == "I" else 0)
shs['external'] = shs['userType'].apply(lambda x: 1 if x == "X" else 0)
shs['total'] = shs['external'] + shs['internal']
shs_pivot = shs.pivot_table(shs,index=["l"],aggfunc=np.sum)
shs_pivot

shs_usertype_pivot = shs.pivot_table(shs,index=["userType"],aggfunc=np.sum)
shs_usertype_pivot
shs_usertype_pivot.total.sum()



all_employees_on_shs_locations_file = r'D:\compusafe\Kunden\shs\baselining\scd_all_employees_on_shs_locations_2021-10-04.csv'
all_employees_on_shs_locations = pd.read_csv(all_employees_on_shs_locations_file, sep = ';', encoding = 'cp1252', dtype = 'str')
all_employees_on_shs_locations.replace(np.NaN,"-", inplace = True)
all_employees_on_shs_locations['internal'] = all_employees_on_shs_locations['userType'].apply(lambda x: 1 if x == "I" else 0)
all_employees_on_shs_locations['external'] = all_employees_on_shs_locations['userType'].apply(lambda x: 1 if x == "X" else 0)
all_employees_on_shs_locations['total'] = all_employees_on_shs_locations['external'] + all_employees_on_shs_locations['internal']
all_employees_on_shs_locations_pivot = all_employees_on_shs_locations.pivot_table(all_employees_on_shs_locations,index=["l"],aggfunc=np.sum)
all_employees_on_shs_locations_pivot
all_employees_on_shs_locations_pivot.to_clip_board()

shs_from_all_employees_on_shs_locations = all_employees_on_shs_locations[all_employees_on_shs_locations['department'].str.contains('^SHS',case = False)]
shs_from_all_employees_on_shs_locations
shs_from_all_employees_on_shs_locations['internal'] = shs_from_all_employees_on_shs_locations['userType'].apply(lambda x: 1 if x == "I" else 0)
shs_from_all_employees_on_shs_locations['external'] = shs_from_all_employees_on_shs_locations['userType'].apply(lambda x: 1 if x == "X" else 0)
shs_from_all_employees_on_shs_locations['total'] = shs_from_all_employees_on_shs_locations['external'] + shs_from_all_employees_on_shs_locations['internal']
shs_from_all_employees_on_shs_locations_pivot = shs_from_all_employees_on_shs_locations.pivot_table(shs_from_all_employees_on_shs_locations,index=["l"],aggfunc=np.sum)
shs_from_all_employees_on_shs_locations_pivot
shs_from_all_employees_on_shs_locations_pivot.to_clipboard()


all_employees_on_shs_locations_usertype_pivot = all_employees_on_shs_locations.pivot_table(all_employees_on_shs_locations,index=["userType"],aggfunc=np.sum)
all_employees_on_shs_locations_usertype_pivot
all_employees_on_shs_locations_usertype_pivot.total.sum()



shs_employees_per_location = shs['l'].value_counts(ascending=False)
#shs_employees_per_location = pd.DataFrame(shs['l'].value_counts(ascending=False),columns=['sal', 'count'])
#pd.DataFrame(shs['l'].value_counts(ascending=False),columns=['sal', 'count'])
shs_locations = pd.DataFrame(shs['l'].unique(),columns=['sal'])

############################ scd analysis for shs end ###################

#import socket

def check_port(ip, port):
    import socket
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #a_socket.settimeout(timeout) #Timeout in seconds
    location=(ip,port)
    result_of_check = a_socket.connect_ex(location)
    a_socket.close()
    if result_of_check == 0:
        return("open")
    else:
        return("closed")

#
import socket
hostip = socket.gethostbyname('scd.siemens.com')
print(socket.gethostbyaddr(hostip))


check_port('127.0.0.1',80,1)


socket.gethostname() # get local hostname

# Import libraries
import dns.resolver
# Finding A record
dns_str='scd.siemens.net'
result = dns.resolver.resolve(dns, 'A')
# Printing record
for val in result:
    print('A Record : ', val.to_text())

# Finding AAAA record
result = dns.resolver.query(dns_str, 'AAAA')
# Printing record
for val in result:
    print('AAAA Record : ', ipval.to_text())

async def wait_host_port(host, port, duration=10, delay=2):
    """Repeatedly try if a port on a host is open until duration seconds passed
    
    Parameters
    ----------
    host : str
        host ip address or hostname
    port : int
        port number
    duration : int, optional
        Total duration in seconds to wait, by default 10
    delay : int, optional
        delay in seconds between each try, by default 2
    
    Returns
    -------
    awaitable bool
    """
    tmax = time.time() + duration
    while time.time() < tmax:
        try:
            _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            if delay:
                await asyncio.sleep(delay)
    return False

#



################ pandas json normalizing start #########################
import requests
from pandas import json_normalize
url = 'https://www.energidataservice.dk/proxy/api/datastore_search?resource_id=nordpoolmarket&limit=5'

response = requests.get(url)
dictr = response.json()
recs = dictr['result']['records']
df = json_normalize(recs)
print(df)

########################################## or ###############
#You could first import your json data in a Python dictionnary :
data = json.loads(elevations)
#Then modify data on the fly :
for result in data['results']:
    result[u'lat']=result[u'location'][u'lat']
    result[u'lng']=result[u'location'][u'lng']
    del result[u'location']
Rebuild json string :
elevations = json.dumps(data)
#Finally :
pd.read_json(elevations)

########################################## or ##################
"""
The problem is that you have several columns in the data frame that contain dicts with smaller dicts inside them. 
Useful Json is often heavily nested. I have been writing small functions that pull the info I want out into a new column. 
That way I have it in the format that I want to use.
"""
for row in range(len(data)):
    #First I load the dict (one at a time)
    n = data.loc[row,'dict_column']
    #Now I make a new column that pulls out the data that I want.
    data.loc[row,'new_column'] = n.get('key')

#
################ pandas json normalizing end #########################


############### elastic dashboard imports #############################################
energy_grey_dst_top = pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\policies\Energy Greyrule Analysis experimental (Alois).csv')
energy_grey_ports_top = pd.read_csv(r'D:\compusafe\Kunden\pg\00_cofw\policies\Energy _greyrule_table_src_dst_ports experimental (Alois).csv')

grey_dst_top20 = pd.read_csv(r'D:\tmp\Energy top 20 Destinations by Grey rule_2021-08-23.csv')
grey_dst_top20
grey_src_top20 = pd.read_csv(r'D:\tmp\Energy top 20 Source by Grey_2021-08-23.csv'),

################################## darwin log #########################################
################################## darwin log #########################################
################################## darwin log #########################################
'''
 0   num                      191486 non-null  int64
 1   date                     191486 non-null  object
 2   time                     191486 non-null  object
 3   orig                     191486 non-null  object
 4   type                     191486 non-null  object
 5   action                   191486 non-null  object
 6   alert                    191486 non-null  object
 7   i/f_name                 191486 non-null  object
 8   i/f_dir                  191486 non-null  object
 9   origin_id                191486 non-null  object
 10  UP_match_table           191486 non-null  object
 11  rule_name                191486 non-null  object
 12  src                      191486 non-null  object
 13  dst                      191486 non-null  object
 14  proto                    191486 non-null  object
 15  service                  191486 non-null  object
 16  s_port                   191486 non-null  object
 17  TCP packet out of state  191486 non-null  object
 18  tcp_flags                191486 non-null  object
'''

log = pd.read_csv(r'D:\compusafe\Kunden\darwin\darwin_cofw_logs\2021-11-11_000000.log_export.txt.gz',sep = ';',usecols=[3,4,5,7,8,11,12,13,14,15])
log = pd.read_csv(r'D:\compusafe\Kunden\darwin\darwin_cofw_logs\2021-11-26_000000.log_export.txt.gz',sep = ';',usecols=[3,4,5,7,8,11,12,13,14,15])
log = pd.read_csv(r'D:\compusafe\Kunden\darwin\darwin_cofw_logs\2021-12-22_000000.log_export.txt.gz',sep = ';',usecols=[3,4,5,7,8,11,12,13,14,15])
log = pd.read_csv(r'D:\compusafe\Kunden\darwin\darwin_cofw_logs\2022-01-15_000000.log_export.txt.gz',sep = ';',usecols=[3,4,5,7,8,11,12,13,14,15])
log = pd.read_csv(r'D:\compusafe\Kunden\darwin\darwin_cofw_logs\2022-01-19_000000.log_export.txt.gz',sep = ';',usecols=[3,4,5,7,8,11,12,13,14,15])
log = pd.read_csv(r'D:\compusafe\Kunden\darwin\darwin_cofw_logs\2022-02-09_000000.log_export.txt.gz',sep = ';',usecols=[3,4,5,7,8,11,12,13,14,15])

log.replace(np.NaN,"-", inplace = True)
log['pair'] =  log['src'] + '_' + log['dst']
log.rename(columns={'Unnamed: 11': 'rule_name'},inplace=True)
log['connects'] = 1
#check unknown ips

log_src_ips = log[['src']]
log_src_ips = log_src_ips.rename(columns={'src': 'ip'})
log_dst_ips = log[['dst']] 
log_dst_ips = log_dst_ips.rename(columns={'dst': 'ip'})

log_ip_unique = pd.concat([log_src_ips,log_dst_ips],ignore_index=True)
log_ip_unique = log_ip_unique.drop_duplicates(subset=['ip'])
ip_unique_check = pd.merge(left=log_ip_unique, right=sysdb, how='left', left_on='ip', right_on='ip') #check if ip known in sysdb
ip_unique_check = ip_unique_check.fillna('-')
ip_unique_check_unknown_in_sysdb = ip_unique_check[(ip_unique_check['c']=='-')] # unknown ips in sysdb
ip_unique_check_unknown_in_sysdb = ip_unique_check_unknown_in_sysdb[ip_unique_check_unknown_in_sysdb['ip'] != '-']
ip_unique_check_unknown_in_sysdb['ip_cidr'] = ip_unique_check_unknown_in_sysdb.apply(lambda x: get_ip_range(x['ip']) , axis=1) # get snic values
ip_unique_check_unknown_in_sysdb = pd.merge(left = ip_unique_check_unknown_in_sysdb, right=snic, how = 'left', left_on='ip_cidr', right_on='IP range/CIDR')
ip_unique_check_unknown_in_sysdb.replace(np.NaN,"-", inplace = True)
ip_unique_check_unknown_in_sysdb = ip_unique_check_unknown_in_sysdb[ip_unique_check_unknown_in_sysdb['IP range/CIDR'] != '-']
ip_unique_check_unknown_in_sysdb['c'] = ip_unique_check_unknown_in_sysdb['Country']
ip_unique_check_unknown_in_sysdb['l'] = ip_unique_check_unknown_in_sysdb['Location']
ip_unique_check_unknown_in_sysdb['snic_comment'] = ip_unique_check_unknown_in_sysdb['Comment']
ip_unique_check_unknown_in_sysdb.drop(ip_unique_check_unknown_in_sysdb.iloc[:, 24:], inplace = True, axis = 1)
ip_unique_check_unknown_in_sysdb['sys_type'] = ip_unique_check['snic_comment'].apply(auto_comment)

ipl = ip_unique_check_unknown_in_sysdb['ip']
ipl.to_csv(r'\\defthw99m5bsrv.ad001.siemens.net\powershell\ip.txt', index = False, header = None)
cmd = 'Invoke-Command -ComputerName DEFTHW99M5BSRV -FilePath d:\powershell\pyip2dns.ps1'
completed = subprocess.run(["powershell", "-Command", cmd])
#\\defthw99m5bsrv.ad001.siemens.net\powershell\dns.csv
ip_dns = pd.read_csv(r'\\defthw99m5bsrv.ad001.siemens.net\powershell\dns.csv',sep=';') #get dns after running get-dns-by-ips.ps1
ip_dns = ip_dns.replace('DNS n/a','-')

maintain = pd.merge(left = ip_unique_check_unknown_in_sysdb, right = ip_dns, how = 'left' , left_on='ip', right_on='IP' )
maintain['dns'] = maintain['DNS']
del(maintain['DNS'])
del(maintain['IP'])

sysdb.replace(np.NaN,'-', inplace=True)
maintain.replace(np.NaN,'-', inplace=True)
maintain['last_modified'] = today
maintain
#snic expansion
maintain['ip_cidr'] = maintain.apply(lambda x: get_ip_range(x['ip']) , axis=1)
snic_reduced = snic[['Country','Location','Comment','IP range/CIDR','VPN name']]
maintain = pd.merge(left = maintain, right=snic_reduced, how='left', left_on='ip_cidr', right_on='IP range/CIDR')
maintain['c'] = maintain['Country']
maintain['l'] = maintain['Location']
maintain['snic_comment'] = maintain['Comment']
maintain['vpn_name'] = maintain['VPN name']

del maintain['Country']
del maintain['Location']
del maintain['Comment']
del maintain['IP range/CIDR']
del maintain['VPN name']
maintain.replace(np.NaN,'-', inplace=True)
maintain
maintain.drop(maintain.iloc[:, 24:], inplace = True, axis = 1)


maintain.to_clipboard(index = None)





maintain_1 = maintain
maintain_1[maintain_1['dns'] != '-']

def get_hostname_from_dns(d):
    d_str = str(d)
    result = '-'
    if (d_str != '-'):
        splitted = d_str.split('.', 1)
        result = splitted[0]
    return(result)

#

def get_domain_from_dns(d):
    d_str = str(d)
    result = '-'
    if (d_str==''):
        d_str="-"
    if (d_str != '-'):
        splitted = d_str.split('.', 1)
        if len(splitted)>0:
            result = splitted[1]
    return(result)

#


maintain_1['hostname'] = maintain_1['dns'].apply(lambda x: get_hostname_from_dns(x))
maintain_1['domain'] = maintain_1['dns'].apply(lambda x: get_domain_from_dns(x))



maintain_1['hostname'].apply(lambda x: if x != '-': x['dns'].split(".")[0])

#zurück99
sysdb = sysdb[~sysdb.ip.isin(maintain.ip)] #delete all maintain.ip in sysdb
sysdb = pd.concat([sysdb,maintain],ignore_index=True)
sysdb['info'] = sysdb['sys_type'] + '|' + sysdb['dns'] + '|' + sysdb['corpflag'] + '|' + sysdb['info_extra'] + '|' + sysdb['managed_by_mail'] + '|' + sysdb['description'] + '|' + sysdb['snic_comment'] + '|' + sysdb['ip_cidr'] + '|' + sysdb['c'] + '|' + sysdb['l']
region = pd.read_csv('d:\\tmp\\region.csv',sep = ';')
sysdb =  pd.merge(left = sysdb, right=region, how='left', left_on='c', right_on='c')
sysdb['region_x'] = sysdb['region_y']
del (sysdb['region_y'])
sysdb = sysdb.rename(columns={'region_x': 'region'})
sysdb = sysdb.replace(np.NaN,"")
sysdb.tail(50)
#delete list of ip from clipboard
#ipl = pd.read_clipboard(header=None,names=['ip'])
#sysdb = sysdb[~sysdb.ip.isin(ipl.ip)] #delete all maintain.ip in sysdb
#sysdb[sysdb['ip'] != '139.23.212.205']

#delete column 24
#sysdb.drop(sysdb.columns[[24]], axis = 1, inplace = True)
#
#store sysdb to csv
#sysdb.to_csv(r'd:\php\sysdb_'+today+'.gz', sep = ';', index = False, encoding = 'utf-8')
######################################################################################################

#further scripting for darwin

ip_unique_check_unknown_in_sysdb_x_snic = pd.merge(left=ip_unique_check_unknown_in_sysdb, right=snic, how='left', left_on='ip', right_on='ip') #check if ip known in sysdb

#add new column with auto_comment
ip_unique_check['zzz'] = ip_unique_check['Comment'].apply(auto_comment)
ip_unique_check.to_csv(ip_zzz,sep=';',encoding = 'cp1252')
ip_unique_check['IP'].to_csv(r'\\139.23.160.99\d$\powershell\ip.txt', index = False, header = False)

################################ darwin radar ###################################################
darwin_radar = pd.read_excel(r'D:\tmp\LNS_Darwin-Migration-Radar.xlsx')
darwin_radar
darwin_radar.to_excel(r'D:\tmp\LNS_Darwin-Migration-Radar_x.xlsx', index = None)


###################################################################################################################
#           Achtung vorher auf Server get-dns-by-ips.ps1 laufen lassen
import subprocess
#cmd = 'Invoke-Command -ComputerName DEFTHW99M5BSRV -FilePath d:\powershell\get-dns-by-ips.ps1'
cmd = 'Invoke-Command -ComputerName DEFTHW99M5BSRV -FilePath d:\powershell\pyip2dns.ps1'
completed = subprocess.run(["powershell", "-Command", cmd])
####################################################################################################################


dns = pd.read_csv(r'\\139.23.160.99\d$\powershell\dns.csv',sep=';') #get dns after running get-dns-by-ips.ps1



log = log[log['rule_name']=='GreyRuleDisabling']
2022-02-09.log_export.xlsx

log_agg = log.groupby('pair',as_index=False).agg({'connects':'sum'})
log_agg.sort_values('connects', inplace = True, ascending = False)
log_agg

log_grey = log[log['rule_name'] == 'greyrule_red2blue']
log_grey_agg = log_grey.groupby('pair',as_index=False).agg({'connects':'sum'})
log_grey_agg.sort_values('connects', inplace = True, ascending = False)
log_grey[log_grey['dst'].str.contains('^172.')]
log_grey[log_grey['dst'].str.contains('^172.')]['dst'].value_counts()
log_grey
log_grey_agg[['src','dst']] = log_grey_agg.pair.str.split("_",expand=True)
log_grey_agg
log_analysis = pd.merge(left = log_grey_agg, right = sysdb[['ip','c','l','info','ip_cidr']], how = 'left',left_on='src', right_on='ip')
del (log_analysis['ip'])
log_analysis = log_analysis.rename(columns={'c': 'src_c', 'l': 'src_l', 'info': 'src_info','ip_cidr': 'src_ip_cidr'})
log_analysis = pd.merge(left = log_analysis, right = sysdb[['ip','c','l','info','ip_cidr']], how = 'left',left_on='dst', right_on='ip')
log_analysis = log_analysis.rename(columns={'c': 'dst_c', 'l': 'dst_l', 'info': 'dst_info','ip_cidr': 'dst_ip_cidr'})
del (log_analysis['ip'])
log_analysis.replace(np.NAN,'-',inplace = True)
#del(log_analysis_dc['pair'])
log_analysis
D:\compusafe\Kunden\darwin\darwin_cofw_logs\2021-11-11_analysis.xlsx





#log_analysis.to_csv(r'D:\compusafe\Kunden\darwin\darwin_cofw_logs\2021-11-11_analysis.csv',sep = ';', index = None)

#zurück4

################################## darwin log #########################################
################################## darwin log #########################################
################################## darwin log #########################################

################ darwin ruleset by fw export ####################################
ifile = r'D:\compusafe\Kunden\darwin\darwin_cofw\darwin_policy_2021-10-28.csv'
darwin_rules = pd.read_csv(ifile)
darwin_rules
darwin_rules.to_excel(r'D:\tmp\darwin_rules.xlsx')



################################## ecd #############################################
ecd = pd.read_csv(r'D:\compusafe\Kunden\pg\baselining\scd_all_SE_employees_2021-06-23.csv',sep = ';',encoding='cp1252' )
ecd.replace(np.NaN,'-', inplace=True)
ecd[ecd['mail'].str.contains('bluschke',case=False)].T


################################## snic Auswertungen ################################## 
snic[(snic['VPN name'] == 'Siemens') & (snic['Comment'].str.contains('(VDI|Virtual Desktop)',case = False))]
snic[(snic['VPN name'] == 'Siemens VPN') & (snic['Comment'].str.contains('(VDI*Clients|Virtual*Desktop*Clients|DV*Clients|vDWP)',case = False))].Comment.head(50)
snic[(snic['VPN name'] == 'Siemens VPN') & (snic['Comment'].str.contains('(vdi|vdwp|virtual client)',case = False))][['Country','Location','Range','Comment']]
snic[(snic['VPN name'] == 'Siemens VPN') & (snic['Comment'].str.contains('(vdi|vdwp|virtual|citrix)',case = False))][['Country','Location','Range','Comment']].head(55)
snic[(snic['VPN name'] == 'Siemens VPN') & (snic['Comment'].str.contains('(vdi|vdwp|virtual|citrix|vdesk)',case = False))][['Country','Location','Range','Comment']].to_clipboard(index=None)
snic_virtual = snic[(snic['VPN name'] == 'Siemens VPN') & (snic['Comment'].str.contains('(vdi|vdwp|virtual|citrix|vdesk|DV_Client)',case = False))].sort_values('Location')

snic_virtual = snic[(snic['VPN name'] == 'Siemens VPN') & (snic['Comment'].str.contains('(vdi|vdwp|virtual|citrix|vdesk|DV_Client)',case = False))].sort_values(['Country','Location'])
snic_virtual[['Country','Location','Range','Comment']]
snic_virtual[['Country','Location','Range','Comment']].to_clipboard(index=None)
snic_virtual.to_clipboard(index=None)

                                    DNS               IP
0  INGGNM7QA21.ad101.siemens-energy.net  132.186.119.154
1                    www.siemens.com.br    129.214.83.52
INGGNM7QA21.ad101.siemens-energy.net|www.siemens.com.br


############################# convert csv to xlsx , Checkpoint WEB Portal Export ###########################################
file = r'\\defthw99m5bsrv.ad001.siemens.net\d$\tmp\Logs_Dec_1__2021_10_35_25_418_AM.zip'
file = r'\\defthw99m5bsrv.ad001.siemens.net\d$\tmp\Logs_Dec_1__2021_22_47_46_991_PM.zip'
file = r'\\defthw99m5bsrv.ad001.siemens.net\d$\tmp\Logs_Dec_8__2021_20_23_41_546_PM_Grey_Black2blue.zip'
file = r'\\defthw99m5bsrv.ad001.siemens.net\d$\tmp\Logs_Dec_13__2021_14_52_44_974_PM.zip'
file = r'\\defthw99m5bsrv.ad001.siemens.net\d$\tmp\Logs_Dec_16__2021_12_19_11_094_PM.zip'
file = r'\\defthw99m5bsrv.ad001.siemens.net\d$\tmp\Logs_Dec_16__2021_14_25_00_551_PM.zip'
file = r'\\defthw99m5bsrv.ad001.siemens.net\d$\tmp\Logs_Dec_16__2021_22_22_49_268_PM.zip'
file = r'\\defthw99m5bsrv.ad001.siemens.net\d$\tmp\Logs_Dec_17__2021_14_08_31_127_PM.zip'

file_csv = pd.read_csv(file,dtype = 'str',error_bad_lines=False,warn_bad_lines=True)#,encoding = 'cp1252', usecols=['IP','normed IP','Country', 'Location', 'Comment']))
#file_csv = file_csv[['Action','Type','Interface','Origin','Source','Destination','Service','Access Rule Name']]
file_csv['Source'] = file_csv.Source.str.extract('(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') #extract pure ip
file_csv['Destination'] = file_csv.Destination.str.extract('(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')#extract pure ip
file_csv
file_csv['Destination Port']
file_csv.to_excel(r'Logs_Dec_17__2021_14_08_31_127_PM.xlsx')


file_csv_red2blue = file_csv[file_csv['Interface'].str.contains('2$')] #direction = red2blue
file_csv_red2blue
file_csv_red2blue['pair'] = 'src:' + file_csv_red2blue['Source'] + ' dst:' + file_csv_red2blue['Destination']
file_csv_red2blue['connects'] = 1
file_csv_red2blue_agg = file_csv_red2blue.groupby('pair',as_index=False).agg({'connects':'sum'})
file_csv_red2blue_agg.sort_values('connects', ascending = False,inplace = True)
file_csv_red2blue_agg[['Source','Destination']] = file_csv_red2blue_agg.pair.str.split(" ",expand=True)

file_csv_red2blue_agg['Source'] = file_csv_red2blue_agg.Source.str.extract('(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') #extract pure ip
file_csv_red2blue_agg['Destination'] = file_csv_red2blue_agg.Destination.str.extract('(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') #extract pure ip

file_csv_red2blue_agg_x = pd.merge(left = file_csv_red2blue_agg, right = sysdb[['ip','c','l','info','ip_cidr']], how = 'left',left_on='Source', right_on='ip')
file_csv_red2blue_agg_x = file_csv_red2blue_agg_x.rename(columns={'c': 'src_c', 'l': 'src_l', 'info': 'src_info','ip_cidr': 'src_ip_cidr','ip': 'src'})
del(file_csv_red2blue_agg_x['Source'])

file_csv_red2blue_agg_x = pd.merge(left = file_csv_red2blue_agg_x, right = sysdb[['ip','c','l','info','ip_cidr']], how = 'left',left_on='Destination', right_on='ip')
file_csv_red2blue_agg_x = file_csv_red2blue_agg_x.rename(columns={'c': 'dst_c', 'l': 'dst_l', 'info': 'dst_info','ip_cidr': 'dst_ip_cidr','ip': 'dst'})
del (file_csv_red2blue_agg_x['Destination'])
file_csv_red2blue_agg_x.replace(np.NAN,'-',inplace = True)
#del(file_csv_red2blue_agg_x['pair'])
file_csv_red2blue_agg_x
#


#file_csv_red2blue_agg_x.to_excel(file+'.xlsx', index = None)


#file_csv_blue2red = file_csv[file_csv['Interface'].str.contains('1$')] #direction = blue2red
#file_csv_blue2red



#file_csv.to_excel(r'd:\tmp\Logs_Dec_1__2021_22_47_46_991_PM.xlsx', index = None)
############################# convert csv to xlsx ###########################################


############################# sysdb seek ####################################################

sysdb[sysdb['info'].str.contains('defthw990pvsrv.ad001.siemens.net',case = False)]

sysdb = pd.merge(left = sysdb, right=snic[['IP range/CIDR','VPN name']], how='left', left_on='ip_cidr', right_on='IP range/CIDR')
sysdb = sysdb.replace(np.NaN,"")
del (sysdb['IP range/CIDR'])


################### traceroute #############################
import asyncio
import mtrpacket

async def trace():
    async with mtrpacket.MtrPacket() as mtr:
        for ttl in range(1, 256):
            result = await mtr.probe('scd.siemens.com', ttl=ttl)
            print(result)
            if result.success:
                break

asyncio.get_event_loop().run_until_complete(trace())

############################### DC Domain Controller on a certain location ###################################
sysdb[(sysdb['sys_type'].str.contains('^dc',case=False))&(sysdb['l'].str.contains('^PLE',case=False))]
sysdb[(sysdb['sys_type'].str.contains('^dc',case=False))&(sysdb['l'].str.contains('^NTH B',case=False))&(sysdb['dns']!='-')]
sysdb[(sysdb['sys_type'].str.contains('^dc',case=False))&(sysdb['l'].str.contains('^MCH P',case=False))&(sysdb['dns'].str.contains('\.net',case=False))]
sysdb[sysdb['info'].str.contains('DEMCHP99NG1SRV',case=False)]

####################### Darwin Grey Rule Reporting from Elastic #########################################################################
dtype_dic= { 'Top values of destination':str, 'Top values of destination.port':str, 'Count of records':str}
darwin_grey_rule_report_top_100 = pd.read_csv(r'D:\compusafe\Kunden\darwin\darwin_cofw\Darwin top 20 Destinations by Grey rule _2022-01-19.csv',dtype = dtype_dic)
darwin_grey_rule_report_top_100.to_excel(r'D:\compusafe\Kunden\darwin\darwin_cofw\Darwin top 20 Destinations by Grey rule _2022-01-19.xlsx',index =None)
darwin_grey_rule_report_top_100.sort_values(by="Count of records",ascending=False,inplace=True)
darwin_grey_rule_report_top_100.replace(",","",inplace = True)
#darwin_grey_rule_report_top_100['Count of records'] = darwin_grey_rule_report_top_100['Count of records'].astype(int)


####### SE LOG DNS analysis #######

log_dns_file_input =r'D:\compusafe\Kunden\pg\00_cofw\se_analysis\se_cofw_logs\2022-01-27.log_export_red.txt.src-dst.csv.gz'

log_dns = pd.read_csv(log_dns_file_input, sep = ';')
log_dns
log_dns.replace(np.NaN,"",inplace = True)
log_dns = log_dns[log_dns['ports'].str.contains('_53,',case = False)]
log_dns = log_dns[log_dns['rule_name'] != 'Cleanup rule']
log_dns.sort_values('connects', ascending = False, inplace = True)
log_dns = log_dns[['src','dst','connects','rule_name','ports','acceptance','orig']]
log_dns = log_dns[log_dns['rule_name'] != 'Cleanup rule']
log_dns.sort_values('connects', ascending = False, inplace = True)
log_dns = pd.merge(left = log_dns, right = sysdb[['ip','c','l','info']], how = 'left', left_on = 'src', right_on = 'ip')
del(log_dns['ip'])
log_dns.rename(columns={"c": "src_c","l": "src_l","info": "src_info"}, inplace = True)
log_dns = pd.merge(left = log_dns, right = sysdb[['ip','c','l','info']], how = 'left', left_on = 'dst', right_on = 'ip')
del(log_dns['ip'])
log_dns.rename(columns={"c": "dst_c","l": "dst_l","info": "dst_info"}, inplace = True)
log_dns


