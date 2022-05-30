#409 where ip,app-id cardinality!=1
SELECT ips,app_id,cardinality,g_dns2 as fqdn,g_change_type,g_s_ip_cidr as list_snic_network,g_s_vpn_name as list_snic_vpn FROM white_apps_se_ruleset
WHERE cardinality!=1;

#222
SELECT COUNT(*) FROM white_apps_se_ruleset_merged_dns2 WHERE dns4 IS NULL;
SELECT * FROM white_apps_se_ruleset_merged_dns2 
LEFT JOIN (SELECT `0` as dip FROM eagle) as e
ON white_apps_se_ruleset_merged_dns2.ips=e.dip
WHERE dns4 AND (e.dip IS NULL) IS NULL LIMIT 10000;

#requires 
#white_apps_se-ruleset
#white_apps_se_ruleset_merged
#white_apps_se_ruleset_merged_dns2
#white_apps_dns
#sysdb
SET group_concat_max_len=15000;

#wa left join st_ports
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id) as wa LEFT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name) 
as ports
ON wa.IPs = ports.st_dest_ip
LEFT JOIN (SELECT `0` as dip FROM eagle) as e
ON wa.ips=e.dip 
WHERE (ports.st_dest_ip IS NULL) AND (e.dip IS NULL) LIMIT 30000;

#white_apps unique ip app_id RIGHT JOIN st_ports unique ip, rule_name 
SELECT ports.* FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
) as wa 
RIGHT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports 
ON wa.ips = ports.st_dest_ip
LEFT JOIN (SELECT `0` as dip FROM eagle) as e
ON ports.st_dest_ip=e.dip
WHERE (wa.ips IS NULL) AND (e.dip IS NULL) LIMIT 30000;