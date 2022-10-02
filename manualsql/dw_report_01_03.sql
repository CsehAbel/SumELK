USE DARWIN_DB;
#427
SELECT COUNT(*) FROM darwin_white_apps_merged_dns2 WHERE dns4 IS NULL;
SELECT * FROM darwin_white_apps_merged_dns2 WHERE dns4 IS NULL LIMIT 10000;
SELECT * FROM eagle;
#requires 
#white_apps_se-ruleset
#white_apps_se_ruleset_merged
#white_apps_se_ruleset_merged_dns2
#white_apps_dns
#sysdb
SET group_concat_max_len=15000;

#wa left join st_ports
SELECT * FROM (SELECT * FROM darwin_white_apps_merged_dns2_grouped_by_ip_app_id) as wa LEFT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip
LEFT JOIN (SELECT ip as dip FROM eagle) as e
ON wa.ips=e.dip
WHERE(ports.st_dest_ip IS NULL) AND (e.dip IS NULL) LIMIT 3000000;

#white_apps unique ip app_id RIGHT JOIN st_ports unique ip, rule_name 
SELECT ports.* FROM (SELECT * FROM darwin_white_apps_merged_dns2_grouped_by_ip_app_id 
) as wa RIGHT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip 
LEFT JOIN (SELECT ip as dip FROM eagle) as e
ON ports.st_dest_ip=e.dip
WHERE (wa.ips IS NULL) AND (e.dip IS NULL) LIMIT 3000000;