USE FOKUS_DB;

#2433703
SELECT COUNT(*) FROM ip;
SELECT * FROM ip;

#2429883
SELECT COUNT(*) FROM ip_unique;
DROP TABLE `ip_unique`;
CREATE TABLE `ip_unique` (
  `id` int NOT NULL AUTO_INCREMENT,
  `src_ip` varchar(15) NOT NULL,
  `dst_ip` varchar(15) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `my_uniq_id` (`src_ip`,`dst_ip`)
) ENGINE=InnoDB AUTO_INCREMENT=262141 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT IGNORE INTO ip_unique (`src_ip`,`dst_ip`)
    SELECT ip.source_ip,ip.dest_ip
    FROM ip;
#SHOW PROCESSLIST;
#python appends the fqdns to this table, select only one fqdn per src_ip
SELECT COUNT(*) FROM src_dns WHERE dns IS NOT NULL;
SELECT COUNT(*) FROM
(SELECT src_ip,MAX(dns) as dns FROM src_dns WHERE dns IS NOT NULL GROUP BY src_ip) as sd;

#ip_unique left join src_dns
SELECT iu.*,src.dns FROM (SELECT * FROM ip_unique) as iu 
LEFT JOIN (SELECT * FROM src_dns WHERE dns IS NOT NULL) as src  ON src.src_ip=iu.src_ip;

#ip_unique left join sysdb
SELECT iu.*,s.dns FROM (SELECT * FROM ip_unique) as iu LEFT JOIN 
(SELECT * FROM sysdb WHERE dns IS NOT NULL AND dns NOT LIKE '-') as s ON iu.src_ip=s.ip
;

#4169
#Filter only all_red_networks_systems
SELECT COUNT(*) FROM systems;

#327827
#Filter out EAGLE
SELECT COUNT(*) FROM eagle;
SELECT ip FROM eagle;
 
SET SESSION group_concat_max_len=1500000; 
 
#show processlist;
#kill 55;
#1366
SELECT COUNT(*) FROM ipunique_g_dns;
DROP TABLE ipunique_g_dns;

CREATE TABLE ipunique_g_dns
SELECT dst_ip,
GROUP_CONCAT(DISTINCT(src_ip)) as s_g_src_ip,
COUNT(src_ip) as countsrc

FROM (SELECT * FROM ip_unique) as i 

LEFT JOIN (SELECT ip as dip FROM eagle) as e
ON i.dst_ip=e.dip 
LEFT JOIN (SELECT `0` as sip FROM systems) as o 
ON i.src_ip=o.sip 
WHERE e.dip IS NULL AND o.sip IS NOT NULL 
GROUP BY dst_ip
#HAVING countsrc=countdns
;

SELECT ipunique_g_dns.*,nice_se_ruleset_st_ports_qc.* FROM nice_se_ruleset_st_ports_qc
INNER JOIN ipunique_g_dns ON nice_se_ruleset_st_ports_qc.ips=ipunique_g_dns.dst_ip ORDER BY countsrc DESC;