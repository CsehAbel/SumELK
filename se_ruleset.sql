USE CSV_DB;

SHOW TABLES;

SELECT group_concat(COLUMN_NAME)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = 'CSV_DB' AND TABLE_NAME = 'white_apps_se_ruleset';

SELECT group_concat(COLUMN_NAME)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = 'CSV_DB' AND TABLE_NAME = 'sysdb';

#wa LEFT JOIN sysdb
CREATE TABLE white_apps_se_ruleset_merged
SELECT ip,dns,c,l,sys_type,corpflag,info_extra,info,hostname,domain,region,snic_comment,ip_cidr,vpn_name
,FQDN,IPs,`Change Type`,`Tufin ID`,`Last modified by Version`,`requested by`,approved_by,`APP ID`,`Source`,FQDNs
,`Application Name`,`Protocol type port`,`ACP Level`
,`TSA expiration date`,`Application Requester`,Comment 
FROM (SELECT * FROM white_apps_se_ruleset) as wa 
LEFT JOIN (SELECT * FROM sysdb) as s 
ON wa.IPs=s.ip;

#TSA expiration date
#filter deleted
SELECT * FROM white_apps_se_ruleset_merged WHERE `Change Type` NOT LIKE 'deleted' LIMIT 10000;
#filter Where App ID is NULL -> no such incorrect record as of 25/02/2022
SELECT * FROM white_apps_se_ruleset_merged WHERE `APP ID` IS NULL AND `Change Type` NOT LIKE 'deleted' LIMIT 20000;

#choose either dns or FQDN (grep/sed of FQDNs)
CREATE TABLE white_apps_se_ruleset_merged_dns2
SELECT ip,c,l,sys_type,corpflag,info_extra,info,hostname,domain,region,snic_comment,ip_cidr,vpn_name
,IPs,`Change Type`,`Tufin ID`,`Last modified by Version`,
`requested by`,approved_by,`APP ID`,`Source`,
`Application Name`,`Protocol type port`,`ACP Level`
,`TSA expiration date`,`Application Requester`,Comment,
CASE WHEN FQDN IS NOT NULL THEN FQDN ELSE dns END AS 'dns2'
FROM white_apps_se_ruleset_merged
WHERE `Change Type` NOT LIKE 'deleted';

DROP TABLE white_apps_se_ruleset_merged_dns2;

#8030
SELECT * FROM white_apps_se_ruleset_merged_dns2 
WHERE dns2 NOT LIKE '-' LIMIT 10000;

#dns2,c,l,info_extra,info,hostname,domain,region,snic_comment,ip_cidr,vpn_name,FQDN,IPs
SELECT * FROM white_apps_se_ruleset_merged_dns2 
WHERE dns2 NOT LIKE '-' AND dns2 IS NOT NULL LIMIT 10000;

#---> THIS IS WHY WE NEED TO GROUP BY IPs !AND APP ID
SELECT * FROM white_apps_se_ruleset_merged_dns2 
WHERE dns2 NOT LIKE '-' AND dns2 IS NOT NULL GROUP BY IPs LIMIT 10000;

#GROUP BY IPs AND APP ID, dns2 is filled but FQDN, FQDNs, dns is not removed
SELECT IPs,`APP ID`,COUNT(*) as cardinality FROM white_apps_se_ruleset_merged_dns2 
WHERE dns2 NOT LIKE '-' AND dns2 IS NOT NULL GROUP BY IPs,`APP ID` LIMIT 10000;

SET group_concat_max_len=15000;

#7447
CREATE TABLE white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id
SELECT IPs,`APP ID`,COUNT(*) as cardinality,GROUP_CONCAT(DISTINCT(ip)),GROUP_CONCAT(DISTINCT(c)),GROUP_CONCAT(DISTINCT(l)),GROUP_CONCAT(DISTINCT(sys_type)),GROUP_CONCAT(DISTINCT(corpflag)),GROUP_CONCAT(DISTINCT(info_extra)),GROUP_CONCAT(DISTINCT(info)),GROUP_CONCAT(DISTINCT(hostname)),GROUP_CONCAT(DISTINCT(domain)),GROUP_CONCAT(DISTINCT(region)),GROUP_CONCAT(DISTINCT(snic_comment)),GROUP_CONCAT(DISTINCT(ip_cidr)),GROUP_CONCAT(DISTINCT(vpn_name
)),GROUP_CONCAT(DISTINCT(`Change Type`)),GROUP_CONCAT(DISTINCT(`Tufin ID`)),GROUP_CONCAT(DISTINCT(`Last modified by Version`)),GROUP_CONCAT(DISTINCT(
`requested by`)),GROUP_CONCAT(DISTINCT(approved_by)),GROUP_CONCAT(DISTINCT(`Source`)),GROUP_CONCAT(DISTINCT(`Application Name`)),GROUP_CONCAT(DISTINCT(`Protocol type port`)),GROUP_CONCAT(DISTINCT(`ACP Level`
)),GROUP_CONCAT(DISTINCT(`TSA expiration date`)),GROUP_CONCAT(DISTINCT(`Application Requester`)),GROUP_CONCAT(DISTINCT(Comment)),GROUP_CONCAT(DISTINCT(dns2))
FROM white_apps_se_ruleset_merged_dns2 
WHERE dns2 NOT LIKE '-' AND dns2 IS NOT NULL GROUP BY IPs,`APP ID`
;


#7447
SELECT IPs,`APP ID`,COUNT(*) as cardinality,GROUP_CONCAT(DISTINCT(ip)),GROUP_CONCAT(DISTINCT(c)),GROUP_CONCAT(DISTINCT(l)),GROUP_CONCAT(DISTINCT(sys_type)),GROUP_CONCAT(DISTINCT(corpflag)),GROUP_CONCAT(DISTINCT(info_extra)),GROUP_CONCAT(DISTINCT(info)),GROUP_CONCAT(DISTINCT(hostname)),GROUP_CONCAT(DISTINCT(domain)),GROUP_CONCAT(DISTINCT(region)),GROUP_CONCAT(DISTINCT(snic_comment)),GROUP_CONCAT(DISTINCT(ip_cidr)),GROUP_CONCAT(DISTINCT(vpn_name
)),GROUP_CONCAT(DISTINCT(`Change Type`)),GROUP_CONCAT(DISTINCT(`Tufin ID`)),GROUP_CONCAT(DISTINCT(`Last modified by Version`)),GROUP_CONCAT(DISTINCT(
`requested by`)),GROUP_CONCAT(DISTINCT(approved_by)),GROUP_CONCAT(DISTINCT(`Source`)),GROUP_CONCAT(DISTINCT(`Application Name`)),GROUP_CONCAT(DISTINCT(`Protocol type port`)),GROUP_CONCAT(DISTINCT(`ACP Level`
)),GROUP_CONCAT(DISTINCT(`TSA expiration date`)),GROUP_CONCAT(DISTINCT(`Application Requester`)),GROUP_CONCAT(DISTINCT(Comment)),GROUP_CONCAT(DISTINCT(dns2))
FROM white_apps_se_ruleset_merged_dns2 
WHERE dns2 NOT LIKE '-' AND dns2 IS NOT NULL GROUP BY IPs,`APP ID`
LIMIT 10000;
 
#409 
SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality!=1;
#409
SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality!=1 GROUP BY IPs,`APP ID` LIMIT 10000;

#7038
SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1 LIMIT 10000;
#7038
SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1 GROUP BY IPs,`APP ID` LIMIT 10000;
 
# white_apps unique ip app_id RIGHT JOIN st_ports unique ip, rule_name 
#9194 -> 9191
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1) as wa RIGHT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)),
GROUP_CONCAT(DISTINCT(st_serv_name)),GROUP_CONCAT(DISTINCT(rule_order)),
GROUP_CONCAT(DISTINCT(rule_number)) FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip WHERE wa.IPs IS NULL LIMIT 30000;

# white_apps unique ip app_id RIGHT JOIN st_ports unique ip
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1) as wa RIGHT JOIN
(SELECT st_dest_ip,GROUP_CONCAT(DISTINCT(rule_name)),GROUP_CONCAT(DISTINCT(st_port)),
GROUP_CONCAT(DISTINCT(st_serv_name)),GROUP_CONCAT(DISTINCT(rule_order)),
GROUP_CONCAT(DISTINCT(rule_number)) FROM st_ports GROUP BY st_dest_ip)
as ports ON wa.IPs = ports.st_dest_ip WHERE wa.IPs IS NULL LIMIT 30000;

#wa inner join st_ports
#9929 -> 9932
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1) as wa INNER JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)),
GROUP_CONCAT(DISTINCT(st_serv_name)),GROUP_CONCAT(DISTINCT(rule_order)),
GROUP_CONCAT(DISTINCT(rule_number)) FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip LIMIT 30000;

#wa left join st_ports
#765
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1) as wa LEFT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)),
GROUP_CONCAT(DISTINCT(st_serv_name)),GROUP_CONCAT(DISTINCT(rule_order)),
GROUP_CONCAT(DISTINCT(rule_number)) FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip WHERE ports.st_dest_ip IS NULL LIMIT 30000;

SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1) as wa LEFT JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)),
GROUP_CONCAT(DISTINCT(st_serv_name)),GROUP_CONCAT(DISTINCT(rule_order)),
GROUP_CONCAT(DISTINCT(rule_number)) FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip WHERE ports.st_dest_ip IS NULL LIMIT 30000;

#INNER JOIN
CREATE TABLE se_ruleset_st_ports
SELECT * FROM (SELECT * FROM white_apps_se_ruleset_merged_dns2_grouped_by_ip_app_id 
WHERE cardinality=1) as wa INNER JOIN
(SELECT st_dest_ip,rule_name,GROUP_CONCAT(DISTINCT(st_port)),
GROUP_CONCAT(DISTINCT(st_serv_name)),GROUP_CONCAT(DISTINCT(rule_order)),
GROUP_CONCAT(DISTINCT(rule_number)) FROM st_ports GROUP BY st_dest_ip,rule_name)
as ports ON wa.IPs = ports.st_dest_ip;

#Needed again because there is no APP ID field in SecureTrack
#So the ports list cannot be yet determined 
SELECT * FROM 
se_ruleset_st_ports GROUP BY IPs,`APP ID` LIMIT 20000;

SELECT * FROM 
se_ruleset_st_ports LIMIT 20000;

#wa_s.*
SELECT * FROM (
SELECT * FROM 
se_ruleset_st_ports)
as wa_s LEFT JOIN 
(SELECT IPs as qc_ip,`APP ID` as qc_app_id,group_concat(DISTINCT(`Application Name`)) as qc_app_name FROM white_apps 
 GROUP BY IPs,`APP ID` HAVING `APP ID` IS NOT NULL) as wa ON wa_s.IPs=wa.qc_ip AND wa_s.`APP ID`=wa.qc_app_id LIMIT 30000;

