USE CSV_DB;
USE CSV_DB;

#239786
SELECT COUNT(*) FROM ip;
SELECT * FROM ip;
#221127
SELECT COUNT(*) FROM ip_unique;
DROP TABLE ip_unique;
CREATE TABLE `ip_unique` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `src_ip` VARCHAR(15) NOT NULL,
  `dst_ip` VARCHAR(15) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `my_uniq_id` (`src_ip`,`dst_ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
SHOW KEYS FROM ip_unique;
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

 #253767
 SELECT COUNT(*) FROM ipunique_ljoin_sysdb_srcdns;
 DROP TABLE ipunique_ljoin_sysdb_srcdns;
 CREATE TABLE ipunique_ljoin_sysdb_srcdns
 SELECT iu.*,CASE WHEN src.dns IS NOT NULL THEN src.dns ELSE s.dns END as dns FROM 
 (SELECT * FROM ip_unique) as iu  
LEFT JOIN (SELECT * FROM src_dns WHERE dns IS NOT NULL) as src 
 ON iu.src_ip=src.src_ip
 LEFT JOIN (SELECT * FROM sysdb
 WHERE dns IS NOT NULL AND dns NOT LIKE '-') as s
 ON iu.src_ip=s.ip;


#Filter out EAGLE
#Filter only all_red_networks_systems
SELECT COUNT(*) FROM systems;

SELECT COUNT(*) FROM eagle; 
 
SET SESSION group_concat_max_len=1500000; 
 
#show processlist;
#kill 55;
#1366
SELECT COUNT(*) FROM ipunique_g_dns;
DROP TABLE ipunique_g_dns;

CREATE TABLE ipunique_g_dns
SELECT dst_ip,
GROUP_CONCAT(DISTINCT(src_ip)) as s_g_src_ip,
GROUP_CONCAT(DISTINCT(dns)) as s_g_dns,
COUNT(dns) as countdns,
#only counts not null
COUNT(src_ip) as countsrc
FROM (SELECT * FROM ipunique_ljoin_sysdb_srcdns) as i 
LEFT JOIN (SELECT ip as dip FROM eagle) as e
ON i.dst_ip=e.dip 
LEFT JOIN (SELECT `0` as sip FROM systems) as o 
ON i.src_ip=o.sip 
WHERE e.dip IS NULL AND o.sip IS NOT NULL 
GROUP BY dst_ip
#HAVING countsrc=countdns
;


#Look at number of source adresses descending
SELECT dst_ip,
GROUP_CONCAT(DISTINCT(dns)) as s_g_dns,
COUNT(dns) as countdns,
#only counts not null
COUNT(src_ip) as countsrc, nice_se_ruleset_st_ports_qc.*
 FROM (SELECT * FROM ipunique_ljoin_sysdb_srcdns) as a 
LEFT JOIN (SELECT ip as dip FROM eagle) as b
ON a.dst_ip=b.dip 
INNER JOIN nice_se_ruleset_st_ports_qc 
ON nice_se_ruleset_st_ports_qc.d_qc_ip=a.dst_ip
WHERE b.dip IS NULL
GROUP BY dst_ip;

#WHERE dns IS NOT NULL AND dns NOT LIKE '-';
SELECT * FROM nice_se_ruleset_st_ports_qc;

#ipunique INNER JOIN se_ruleset_st_ports
SELECT ipunique_g_dns.*,nice_se_ruleset_st_ports_qc.* FROM nice_se_ruleset_st_ports_qc 
INNER JOIN ipunique_g_dns ON nice_se_ruleset_st_ports_qc.ips=ipunique_g_dns.dst_ip ORDER BY countsrc DESC;

SELECT ipunique_g_dns.*,nice_se_ruleset_st_ports_qc.* FROM nice_se_ruleset_st_ports_qc 
INNER JOIN ipunique_g_dns ON nice_se_ruleset_st_ports_qc.ips=ipunique_g_dns.dst_ip WHERE dst_ip LIKE "139.23.230.92" LIMIT 30000;

#se_ruleset_st_ports RIGHT JOIN ipunique
SELECT countsrc,countdns,nice_se_ruleset_st_ports_qc.*,ipunique_g_dns.* FROM nice_se_ruleset_st_ports_qc RIGHT JOIN ipunique_g_dns 
ON nice_se_ruleset_st_ports_qc.ips=ipunique_g_dns.dst_ip
LIMIT 30000;
SELECT COUNT(*) FROM ip_unique;
SELECT COUNT(*) FROM ip_unique;
