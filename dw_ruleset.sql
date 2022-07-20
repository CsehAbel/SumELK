SHOW CREATE DATABASE CSV_DB;
CREATE DATABASE IF NOT EXISTS DARWIN_DB;
SHOW CREATE DATABASE DARWIN_DB;

USE DARWIN_DB;
#darwin_white_apps
SHOW TABLES;

SELECT group_concat(COLUMN_NAME)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = 'DARWIN_DB' AND TABLE_NAME = 'darwin_white_apps';
 
#1355
SELECT COUNT(*) FROM darwin_white_apps;

#filter TSA expiration date
SELECT * FROM darwin_white_apps_merged WHERE '2022-06-31'<tsa OR tsa IS NULL; #1112-<1160
SELECT * FROM darwin_white_apps_merged WHERE tsa<'2022-06-31'; #231->193

SELECT * FROM darwin_white_apps_merged WHERE app_id IS NULL OR app_id LIKE '-'; #7

SET GLOBAL innodb_buffer_pool_size=268435456;
#1357
SELECT COUNT(*) FROM darwin_white_apps_merged;
DROP TABLE darwin_white_apps_merged;
#wa LEFT JOIN sysdb, removing wa.FQDN and sysdb.dns
CREATE TABLE darwin_white_apps_merged
SELECT 
CASE WHEN FQDN IS NOT NULL 
	THEN FQDN ELSE
		CASE WHEN dns LIKE '-' THEN 
			NULL 
		ELSE 
			dns
		END
END AS 'dns2'
,IPs as ips,`APP ID` as app_id
,`Application Name` as app_name,`Protocol type port` as port
,TSA as tsa

,ip
#dns,ip,
,c,l,sys_type,corpflag,info_extra,info,hostname,domain,region,snic_comment,ip_cidr,vpn_name
FROM (SELECT * FROM darwin_white_apps) as wa 
LEFT JOIN (SELECT * FROM sysdb) as s 
ON wa.IPs=s.ip;
#SHOW PROCESSLIST;
#Joining with white_apps_dns(index,IPs,dns)
DROP TABLE darwin_white_apps_merged_dns2;
#choose either dns3 or FQDN (grep/sed of FQDNs)
CREATE TABLE darwin_white_apps_merged_dns2
#dns2 -> from sysdb or (seruleset cleaned fqdn)
SELECT CASE WHEN dns3 IS NOT NULL THEN dns3 ELSE dns2 END AS 'dns4'
,wa.ips,wa.app_id
,wa.port,wa.app_name
,wa.tsa


,ip,   c,l,sys_type,corpflag,info_extra,info,hostname,domain,region
,snic_comment,ip_cidr,vpn_name
,wa_d.ips as wa_d_ips
FROM 
(SELECT * FROM darwin_white_apps_merged) as wa
LEFT JOIN (SELECT IPs,dns as dns3 FROM darwin_white_apps_dns) as wa_d ON wa.ips=wa_d.IPs
WHERE '2022-06-31'<tsa OR tsa IS NULL;

SET group_concat_max_len=15000;

DROP TABLE darwin_white_apps_merged_dns2_grouped_by_ip_app_id;
CREATE TABLE darwin_white_apps_merged_dns2_grouped_by_ip_app_id
SELECT ips,app_id,COUNT(*) as cardinality,
GROUP_CONCAT(DISTINCT(app_name)) as g_app_name,
GROUP_CONCAT(DISTINCT(tsa)) as g_tsa,

GROUP_CONCAT(DISTINCT(ip)) as g_s_ip,
GROUP_CONCAT(DISTINCT(c)) as g_s_c,
GROUP_CONCAT(DISTINCT(l)) as g_s_l,
GROUP_CONCAT(DISTINCT(sys_type)) as g_s_sys_type,
GROUP_CONCAT(DISTINCT(corpflag)) as g_s_corpflag,
GROUP_CONCAT(DISTINCT(info_extra)) as g_s_info_extra,
GROUP_CONCAT(DISTINCT(info)) as g_s_info,
GROUP_CONCAT(DISTINCT(hostname)) as g_s_hostname,
GROUP_CONCAT(DISTINCT(domain)) as g_s_domain,
GROUP_CONCAT(DISTINCT(region)) as g_s_region,
GROUP_CONCAT(DISTINCT(snic_comment)) as g_s_snic_comment,
GROUP_CONCAT(DISTINCT(ip_cidr)) as g_s_ip_cidr,
GROUP_CONCAT(DISTINCT(vpn_name)) as g_s_vpn_name,

GROUP_CONCAT(DISTINCT(port)) as g_port,#dest port

GROUP_CONCAT(DISTINCT(dns4)) as g_dns4 #dest fqdn
FROM darwin_white_apps_merged_dns2 
#WHERE dns4 IS NOT NULL 
GROUP BY ips,app_id
;
 
DROP TABLE dw_ruleset_st_ports;
#INNER JOIN
CREATE TABLE dw_ruleset_st_ports
SELECT * FROM (SELECT * FROM darwin_white_apps_merged_dns2_grouped_by_ip_app_id) as wa INNER JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip;


DROP TABLE nice_dw_ruleset_st_ports;
CREATE TABLE nice_dw_ruleset_st_ports
SELECT
app_id,
ips,
cardinality,
g_app_name as d_g_app_name,
g_tsa as g_tsa,
g_dns4 as d_g_dns4,
g_st_port as d_g_st_port,
rule_name,
g_rule_number,

g_s_c as d_g_s_c,
g_s_ip_cidr as d_g_s_ip_cidr ,
g_s_vpn_name as d_g_s_vpn_name,
g_s_sys_type as d_g_s_sys_type,
g_s_region as d_g_s_region,
g_s_snic_comment as d_g_s_snic_comment,
g_s_info_extra as d_g_s_info_extra,
g_s_info,
g_s_hostname,
g_s_domain,
g_s_corpflag

#.g_port
FROM dw_ruleset_st_ports;


