#409 where ip,app-id cardinality!=1
SELECT ips,app_id,cardinality,g_dns2 as fqdn,g_change_type,g_s_ip_cidr as list_snic_network,g_s_vpn_name as list_snic_vpn FROM white_apps_se_ruleset
WHERE cardinality!=1;

#222
SELECT COUNT(*) FROM white_apps_se_ruleset_merged_dns2 WHERE dns4 IS NULL;
SELECT * FROM white_apps_se_ruleset_merged_dns2 WHERE dns4 IS NULL LIMIT 10000;

#requires 
#white_apps_se-ruleset
#white_apps_se_ruleset_merged
#white_apps_se_ruleset_merged_dns2
#white_apps_dns
#sysdb
SET group_concat_max_len=15000;

DROP TABLE white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id2;
#t-1:7447 t-0:17042 t+1=18195
CREATE TABLE white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id2
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
GROUP_CONCAT(DISTINCT(dns4)) as g_dns4
FROM white_apps_se_ruleset_merged_dns2 
#WHERE dns4 IS NOT NULL 
GROUP BY ips,app_id
;

#wa left join st_ports
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id2) as wa LEFT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(st_serv_name)) as g_st_serv_name,
GROUP_CONCAT(DISTINCT(rule_order)) as g_rule_order,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip WHERE ports.st_dest_ip IS NULL LIMIT 30000;

#white_apps unique ip app_id RIGHT JOIN st_ports unique ip, rule_name 
SELECT ports.* FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id2 
) as wa RIGHT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(st_serv_name)) as g_st_serv_name,
GROUP_CONCAT(DISTINCT(rule_order)) as g_rule_order,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip WHERE wa.ips IS NULL LIMIT 30000;