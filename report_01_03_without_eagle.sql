#1650
SELECT COUNT(*) FROM white_apps_se_ruleset_merged_dns2 WHERE dns4 IS NULL;
SELECT * FROM white_apps_se_ruleset_merged_dns2 
LEFT JOIN (SELECT ip as dip FROM eagle) as e
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
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id) as wa 
LEFT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name) 
as ports
ON wa.IPs = ports.st_dest_ip
LEFT JOIN (SELECT ip as dip FROM eagle) as e
ON wa.ips=e.dip 
WHERE (ports.st_dest_ip IS NULL) AND (e.dip IS NULL) LIMIT 30000;

#white_apps unique ip app_id RIGHT JOIN st_ports unique ip, rule_name 
SELECT ports.*,wa.*,e.* FROM (SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name) as ports 
LEFT JOIN
(SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
) as wa 
ON wa.ips = ports.st_dest_ip
LEFT JOIN (SELECT ip as dip FROM eagle) as e
ON ports.st_dest_ip=e.dip
WHERE (wa.ips IS NULL) AND (e.dip IS NULL) LIMIT 30000;