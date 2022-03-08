USE CSV_DB;

SHOW TABLES;

SELECT group_concat(COLUMN_NAME)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = 'CSV_DB' AND TABLE_NAME = 'white_apps_se_ruleset';

SELECT group_concat(COLUMN_NAME)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = 'CSV_DB' AND TABLE_NAME = 'sysdb';

DROP TABLE white_apps_se_ruleset_merged;
#wa LEFT JOIN sysdb, removing wa.FQDN and sysdb.dns
CREATE TABLE white_apps_se_ruleset_merged
SELECT 
CASE WHEN FQDN IS NOT NULL 
	THEN FQDN ELSE
		CASE WHEN dns LIKE '-' THEN 
			NULL 
		ELSE 
			dns
		END
END AS 'dns2',
ip,
#dns,ip,
c,l,sys_type,corpflag,info_extra,info,hostname,domain,region,snic_comment,ip_cidr,vpn_name
,FQDN as fqdn,IPs as ips,`Change Type` as change_type,`Tufin ID` as tufin_id,`APP ID` as app_id,`Source` as source,FQDNs as fqdns
,`Application Name` as dest_info,`Protocol type port` as port
,`TSA expiration date` as tsa_expiration_date,`Application Requester` as application_requestor,Comment as comment
FROM (SELECT * FROM white_apps_se_ruleset) as wa 
LEFT JOIN (SELECT * FROM sysdb) as s 
ON wa.IPs=s.ip;

#TSA expiration date
#filter deleted
SELECT * FROM white_apps_se_ruleset_merged WHERE change_type NOT LIKE 'deleted' LIMIT 10000;
#filter Where App ID is NULL -> no such incorrect record as of 25/02/2022
SELECT * FROM white_apps_se_ruleset_merged WHERE app_id IS NULL AND change_type NOT LIKE 'deleted' LIMIT 20000;

#Joining with white_apps_dns(index,IPs,dns)
DROP TABLE white_apps_se_ruleset_merged_dns2;
#choose either dns or FQDN (grep/sed of FQDNs)
CREATE TABLE white_apps_se_ruleset_merged_dns2
SELECT CASE WHEN dns3 IS NOT NULL THEN dns3 ELSE dns2 END AS 'dns4',wa.* 
FROM 
(SELECT fqdn,ips,change_type,tufin_id,app_id,source,fqdns
,dest_info,port
,tsa_expiration_date,application_requestor,comment,
CASE WHEN fqdn IS NOT NULL THEN fqdn ELSE dns END AS 'dns2',
ip,dns,c,l,sys_type,corpflag,info_extra,info,hostname,domain,region,
snic_comment,ip_cidr,vpn_name
FROM white_apps_se_ruleset_merged) as wa
LEFT JOIN (SELECT IPs,dns as dns3 FROM white_apps_dns) as wa_d ON wa.ips=wa_d.IPs
WHERE change_type NOT LIKE 'deleted';

SELECT * FROM white_apps_se_ruleset_merged_dns2;

#8030 from 8208
SELECT * FROM white_apps_se_ruleset_merged_dns2 
WHERE dns2 NOT LIKE '-' LIMIT 10000;

#wrong fqdn 162 from 8208
SELECT * FROM white_apps_se_ruleset_merged_dns2 
WHERE dns2 LIKE '-' LIMIT 10000;

#wrong fqdn 16 from 8208
SELECT * FROM white_apps_se_ruleset_merged_dns2 
WHERE dns2 IS NULL LIMIT 10000;

#8030 from 8208
SELECT * FROM white_apps_se_ruleset_merged_dns2 
WHERE dns2 NOT LIKE '-' AND dns2 IS NOT NULL LIMIT 10000;

#---> THIS IS WHY WE NEED TO GROUP BY IPs AND!!! APP ID
SELECT * FROM white_apps_se_ruleset_merged_dns2 
WHERE dns2 NOT LIKE '-' AND dns2 IS NOT NULL GROUP BY IPs LIMIT 10000;

#GROUP BY IPs AND APP ID, dns2 is filled but FQDN, FQDNs, dns is not removed
SELECT ips,app_id,COUNT(*) as cardinality FROM white_apps_se_ruleset_merged_dns2 
WHERE dns2 NOT LIKE '-' AND dns2 IS NOT NULL GROUP BY ips,app_id LIMIT 10000;

SET group_concat_max_len=15000;

DROP TABLE white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id;
#7447
CREATE TABLE white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id
SELECT ips,app_id,COUNT(*) as cardinality,
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
GROUP_CONCAT(DISTINCT(change_type)) as g_change_type,
GROUP_CONCAT(DISTINCT(tufin_id)) as g_tufin_id,
GROUP_CONCAT(DISTINCT(source)) as g_source,
GROUP_CONCAT(DISTINCT(dest_info)) as g_dest_info,
GROUP_CONCAT(DISTINCT(port)) as g_port,
GROUP_CONCAT(DISTINCT(tsa_expiration_date)) as g_tsa_expiration_date,
GROUP_CONCAT(DISTINCT(application_requestor)) as g_application_requestor,
GROUP_CONCAT(DISTINCT(comment)) as g_comment,
GROUP_CONCAT(DISTINCT(dns2)) as g_dns2
FROM white_apps_se_ruleset_merged_dns2 
WHERE dns2 NOT LIKE '-' AND dns2 IS NOT NULL GROUP BY ips,app_id
;
 
#409 
SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality!=1;
#409
SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality!=1 GROUP BY ips,app_id LIMIT 10000;

#7038
SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1 LIMIT 10000;
#7038
SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1 GROUP BY ips,app_id LIMIT 10000;
 
# white_apps unique ip app_id RIGHT JOIN st_ports unique ip, rule_name 
#9194 -> 9191
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1) as wa RIGHT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(st_serv_name)) as g_st_serv_name,
GROUP_CONCAT(DISTINCT(rule_order)) as g_rule_order,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip WHERE wa.ips IS NULL LIMIT 30000;

#8906
# white_apps unique ip RIGHT JOIN st_ports unique ip
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip
WHERE cardinality=1) as wa RIGHT JOIN
(SELECT st_dest_ip,GROUP_CONCAT(DISTINCT(rule_name)) as g_rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(st_serv_name)) as g_st_serv_name,
GROUP_CONCAT(DISTINCT(rule_order)) as g_rule_order,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip)
as ports ON wa.IPs = ports.st_dest_ip WHERE wa.ips IS NULL LIMIT 30000;

#wa inner join st_ports
#9929 -> 9932
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1) as wa INNER JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(st_serv_name)) as g_st_serv_name,
GROUP_CONCAT(DISTINCT(rule_order)) as g_rule_order,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip LIMIT 30000;

#wa left join st_ports
#765
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1) as wa LEFT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(st_serv_name)) as g_st_serv_name,
GROUP_CONCAT(DISTINCT(rule_order)) as g_rule_order,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip WHERE ports.st_dest_ip IS NULL LIMIT 30000;

DROP TABLE se_ruleset_st_ports;
#INNER JOIN
CREATE TABLE se_ruleset_st_ports
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1) as wa INNER JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(st_serv_name)) as g_st_serv_name,
GROUP_CONCAT(DISTINCT(rule_order)) as g_rule_order,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip;

#Needed again because there is no APP ID field in SecureTrack
#So the ports list cannot be yet determined, only a cross join
SELECT * FROM 
se_ruleset_st_ports GROUP BY ips,app_id LIMIT 20000;

DROP TABLE se_ruleset_st_ports_qc;
#getting Application Name from QualityCheck 
#for each dest_ip, app id in se_ruleset_st_ports
CREATE TABLE se_ruleset_st_ports_qc
SELECT * FROM (
SELECT * FROM 
se_ruleset_st_ports)
as wa_s LEFT JOIN 
(SELECT IPs as qc_ip,`APP ID` as qc_app_id,group_concat(DISTINCT(`Application Name`)) as g_qc_app_name FROM white_apps 
 GROUP BY IPs,`APP ID` HAVING `APP ID` IS NOT NULL) as wa ON wa_s.ips=wa.qc_ip AND wa_s.app_id=wa.qc_app_id LIMIT 30000;

SELECT group_concat(COLUMN_NAME)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = 'CSV_DB' AND TABLE_NAME = 'se_ruleset_st_ports_qc';

SHOW COLUMNS FROM se_ruleset_st_ports_qc;

SELECT GROUP_CONCAT(DISTINCT(`ACP Level`)) FROM se_ruleset_st_ports_qc;

CREATE TABLE nice_se_ruleset_st_ports_qc
SELECT
g_qc_app_name,
qc_app_id,
app_id,
ips,
qc_ip,
st_dest_ip,
g_s_ip,
cardinality,
g_dns2,
g_st_port,
rule_name,
g_rule_number,
g_st_serv_name,
g_rule_order,
g_s_c,
g_s_ip_cidr,
g_s_vpn_name,
g_s_sys_type,
g_s_region,
g_s_snic_comment,
g_s_info_extra,
g_s_info,
g_s_hostname,
g_s_domain,
g_s_corpflag
,#g_tsa_expiration_date,
g_application_requestor
#g_comment,
,g_change_type
,g_tufin_id
#,g_source
#,g_dest_info
#.g_port
FROM se_ruleset_st_ports_qc;
