USE FOKUS_DB;

SHOW TABLES;

#353
SELECT COUNT(*) FROM fokus_ruleset;

DROP TABLE IF EXISTS ruleset_merged;
#wa LEFT JOIN sysdb, removing wa.FQDN and sysdb.dns
CREATE TABLE ruleset_merged
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
FROM (SELECT * FROM fokus_ruleset) as wa
LEFT JOIN (SELECT * FROM sysdb) as s 
ON wa.IPs=s.ip;
#SHOW PROCESSLIST;
#Joining with white_apps_dns(index,IPs,dns)
DROP TABLE IF EXISTS ruleset_merged_dns2;
#choose either dns3 or FQDN (grep/sed of FQDNs)
CREATE TABLE ruleset_merged_dns2
#dns2 -> from sysdb or (seruleset cleaned fqdn)
SELECT dns2 as 'dns4'
,wa.ips,change_type,tufin_id,app_id,source
,dest_info,port
,tsa_expiration_date,application_requestor,comment

,ip,   c,l,sys_type,corpflag,info_extra,info,hostname,domain,region
,snic_comment,ip_cidr,vpn_name
FROM 
(SELECT * FROM ruleset_merged) as wa
WHERE change_type NOT LIKE 'deleted';

SET group_concat_max_len=15000;

DROP TABLE IF EXISTS ruleset_merged_dns2_grouped_by_ip_app_id;
CREATE TABLE ruleset_merged_dns2_grouped_by_ip_app_id
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
FROM ruleset_merged_dns2
#WHERE dns4 IS NOT NULL 
GROUP BY ips,app_id
;
 
DROP TABLE IF EXISTS se_ruleset_st_ports;
#INNER JOIN
CREATE TABLE se_ruleset_st_ports
SELECT * FROM (SELECT * FROM ruleset_merged_dns2_grouped_by_ip_app_id) as wa INNER JOIN
(SELECT st_dest_ip,GROUP_CONCAT(DISTINCT(rule_name)) as g_rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip)
as ports ON wa.IPs = ports.st_dest_ip;

DROP TABLE IF EXISTS nice_se_ruleset_st_ports;
CREATE TABLE nice_se_ruleset_st_ports
SELECT
g_dest_info,
app_id,
ips,
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
#,.g_port
FROM se_ruleset_st_ports;
