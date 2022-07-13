USE CSV_DB;

SHOW TABLES;

SELECT group_concat(COLUMN_NAME)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = 'CSV_DB' AND TABLE_NAME = 'white_apps_se_ruleset';

SELECT group_concat(COLUMN_NAME)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = 'CSV_DB' AND TABLE_NAME = 'sysdb';
 
#20728->16180
SELECT COUNT(*) FROM white_apps_se_ruleset;

SELECT group_concat(COLUMN_NAME)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = 'CSV_DB' AND TABLE_NAME = 'se_ruleset_st_ports_qc';

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
END AS 'dns2'
,IPs as ips,`Change Type` as change_type,`Tufin ID` as tufin_id,`APP ID` as app_id,`Source` as source
,`Application Name` as dest_info,`Protocol type port` as port
,`TSA expiration date` as tsa_expiration_date,`Application Requester` as application_requestor,Comment as comment
,ip
#dns,ip,
,c,l,sys_type,corpflag,info_extra,info,hostname,domain,region,snic_comment,ip_cidr,vpn_name
FROM (SELECT * FROM white_apps_se_ruleset) as wa 
LEFT JOIN (SELECT * FROM sysdb) as s 
ON wa.IPs=s.ip;

#Joining with white_apps_dns(index,IPs,dns)
DROP TABLE white_apps_se_ruleset_merged_dns2;
#choose either dns3 or FQDN (grep/sed of FQDNs)
CREATE TABLE white_apps_se_ruleset_merged_dns2
#dns2 -> from sysdb or (seruleset cleaned fqdn)
SELECT CASE WHEN dns3 IS NOT NULL THEN dns3 ELSE dns2 END AS 'dns4'
,wa.ips,change_type,tufin_id,app_id,source
,dest_info,port
,tsa_expiration_date,application_requestor,comment

,ip,   c,l,sys_type,corpflag,info_extra,info,hostname,domain,region
,snic_comment,ip_cidr,vpn_name
,wa_d.ips as wa_d_ips
FROM 
(SELECT * FROM white_apps_se_ruleset_merged) as wa
LEFT JOIN (SELECT IPs,dns as dns3 FROM white_apps_dns) as wa_d ON wa.ips=wa_d.IPs
WHERE change_type NOT LIKE 'deleted';

SET group_concat_max_len=15000;

DROP TABLE white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id;
#t-1:7447 t-0:17042 t+1:18195 t+2:18940
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
GROUP_CONCAT(DISTINCT(port)) as g_port,#dest port
GROUP_CONCAT(DISTINCT(tsa_expiration_date)) as g_tsa_expiration_date,
GROUP_CONCAT(DISTINCT(application_requestor)) as g_application_requestor,
GROUP_CONCAT(DISTINCT(comment)) as g_comment,
GROUP_CONCAT(DISTINCT(dns4)) as g_dns4 #dest fqdn
FROM white_apps_se_ruleset_merged_dns2 
#WHERE dns4 IS NOT NULL 
GROUP BY ips,app_id
;
 
DROP TABLE se_ruleset_st_ports;
#INNER JOIN
CREATE TABLE se_ruleset_st_ports
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id) as wa INNER JOIN
(SELECT st_dest_ip,GROUP_CONCAT(DISTINCT(rule_name)) as g_rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip)
as ports ON wa.IPs = ports.st_dest_ip;

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

DROP TABLE nice_se_ruleset_st_ports_qc;
CREATE TABLE nice_se_ruleset_st_ports_qc
SELECT
g_qc_app_name as d_g_qc_app_name,
qc_app_id,
app_id,
ips,
qc_ip as d_qc_ip,
#st_dest_ip,
#g_s_ip,
cardinality,
g_dns4 as d_g_dns4,
g_st_port as d_g_st_port,
g_rule_name,
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
,#g_tsa_expiration_date,
g_application_requestor
#g_comment,
,g_change_type
,g_tufin_id
#,g_source
#,g_dest_info
#.g_port
FROM se_ruleset_st_ports_qc;
