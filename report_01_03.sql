#409 where ip,app-id cardinality!=1
SELECT ips,app_id,cardinality,g_dns2 as fqdn,g_change_type,g_s_ip_cidr as list_snic_network,g_s_vpn_name as list_snic_vpn FROM white_apps_se_ruleset
WHERE cardinality!=1;

#wa left join st_ports
#765->1315->1190
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1) as wa LEFT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(st_serv_name)) as g_st_serv_name,
GROUP_CONCAT(DISTINCT(rule_order)) as g_rule_order,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip WHERE ports.st_dest_ip IS NULL LIMIT 30000;

#wa left join st_ports
#837(765 cardinality=1)->1442->2116
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id) as wa LEFT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(st_serv_name)) as g_st_serv_name,
GROUP_CONCAT(DISTINCT(rule_order)) as g_rule_order,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip WHERE ports.st_dest_ip IS NULL LIMIT 30000;


# white_apps unique ip app_id RIGHT JOIN st_ports unique ip, rule_name 
#9194 -> 9191 -> 8933 -> 11097
SELECT ports.* FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1) as wa RIGHT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(st_serv_name)) as g_st_serv_name,
GROUP_CONCAT(DISTINCT(rule_order)) as g_rule_order,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip WHERE wa.ips IS NULL LIMIT 30000;

#white_apps unique ip app_id RIGHT JOIN st_ports unique ip, rule_name 
#8925 (8933 where cardindality=1) ->8723 -> 3067
SELECT ports.* FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
) as wa RIGHT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(st_serv_name)) as g_st_serv_name,
GROUP_CONCAT(DISTINCT(rule_order)) as g_rule_order,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip WHERE wa.ips IS NULL LIMIT 30000;