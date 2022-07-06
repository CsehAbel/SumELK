#34384
SELECT COUNT(*) FROM snic_export;
SELECT * FROM snic_export WHERE `USSM` LIKE '%Milbradt%' AND `VPN name` LIKE 'Siemens VPN';
SELECT COUNT(*) FROM snic_export WHERE `USSM` LIKE '%Milbradt%' AND `VPN name` LIKE 'Siemens VPN';
SELECT Location FROM snic_export WHERE `USSM` LIKE '%Milbradt%' AND `VPN name` LIKE 'Siemens VPN' GROUP BY Location;

#323351
SELECT COUNT(*) FROM eagle;

SELECT e.*,wa.* FROM 
(SELECT * FROM white_apps_se_ruleset) as wa 
LEFT JOIN 
(SELECT ip as snic_ip,base as snic_base,cidr as snic_cidr,ussm as snic_ussm,vpn as snic_vpn FROM eagle) as e
ON wa.IPs=e.snic_ip WHERE e.snic_ip IS NOT NULL AND wa.`Change Type` NOT LIKE 'deleted';

SELECT `index`,st_dest_ip,GROUP_CONCAT(DISTINCT(st_port)) as g_port,rule_name,rule_number,e.* 
FROM 
(SELECT * FROM st_ports) as stp 
LEFT JOIN 
(SELECT ip as snic_ip,base as snic_base,cidr as snic_cidr,ussm as snic_ussm,vpn as snic_vpn FROM eagle) as e
ON stp.st_dest_ip=e.snic_ip WHERE e.snic_ip IS NOT NULL group by st_dest_ip ORDER BY snic_ip;