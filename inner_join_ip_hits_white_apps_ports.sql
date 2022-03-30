USE CSV_DB;
USE CSV_DB;

#t-1:161 661 t-0: 195 511
SELECT COUNT(*) FROM ip;
SELECT * FROM ip;

CREATE TABLE `ip_unique` (
  `src_ip` VARCHAR(15) NOT NULL,
  `dst_ip` VARCHAR(15) NOT NULL,
  PRIMARY KEY (`src_ip`,`dst_ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

TRUNCATE TABLE ip_unique;

INSERT IGNORE INTO ip_unique (`src_ip`,`dst_ip`)
    SELECT ip.source_ip,ip.dest_ip
    FROM ip;

#t-1: 17182 t-0: 18053
SELECT src_ip FROM ip_unique GROUP BY src_ip LIMIT 30000; 

#2658
SELECT COUNT(*) FROM src_dns WHERE dns IS NOT NULL;
#17182 -> needs to be updated to match 18053
SELECT COUNT(*) FROM src_dns;

#22936 ip_unique left join src_dns
SELECT iu.*,src.dns FROM (SELECT * FROM ip_unique) as iu 
LEFT JOIN (SELECT * FROM src_dns WHERE dns IS NOT NULL) as src  ON src.src_ip=iu.src_ip;

#38693 ip_unique left join sysdb
SELECT iu.*,s.dns FROM (SELECT * FROM ip_unique) as iu LEFT JOIN 
(SELECT * FROM sysdb WHERE dns IS NOT NULL AND dns NOT LIKE '-') as s ON iu.src_ip=s.ip
;

 #161 540
 SELECT COUNT(*) FROM ip_unique;

#163 091
SELECT iu.*,src.dns,s.dns as dns2 FROM (SELECT * FROM ip_unique) as iu  
LEFT JOIN (SELECT * FROM src_dns WHERE dns IS NOT NULL) as src 
 ON iu.src_ip=src.src_ip
 LEFT JOIN (SELECT * FROM sysdb
 WHERE dns IS NOT NULL AND dns NOT LIKE '-') as s
 ON iu.src_ip=s.ip;
 
 #163 974
 DROP TABLE ipunique_ljoin_sysdb_srcdns;
 CREATE TABLE ipunique_ljoin_sysdb_srcdns
 SELECT iu.*,CASE WHEN src.dns IS NOT NULL THEN src.dns ELSE s.dns END as dns FROM (SELECT * FROM ip_unique) as iu  
LEFT JOIN (SELECT * FROM src_dns WHERE dns IS NOT NULL) as src 
 ON iu.src_ip=src.src_ip
 LEFT JOIN (SELECT * FROM sysdb
 WHERE dns IS NOT NULL AND dns NOT LIKE '-') as s
 ON iu.src_ip=s.ip;

#Filter out EAGLE
#FilterOnlyInOld
 
SET group_concat_max_len=150000; 
 
DROP TABLE ipunique_g_dns;
#519 number of not null dns equals number of source ips
CREATE TABLE ipunique_g_dns
SELECT dst_ip,
GROUP_CONCAT(DISTINCT(src_ip)) as g_src_ip,
GROUP_CONCAT(DISTINCT(dns)) as g_dns,
COUNT(dns) as countdns,
#only counts not null
COUNT(src_ip) as countsrc
FROM ipunique_ljoin_sysdb_srcdns GROUP BY dst_ip
#HAVING countsrc=countdns
;

#WHERE dns IS NOT NULL AND dns NOT LIKE '-';
SELECT * FROM nice_se_ruleset_st_ports_qc;

#ipunique INNER JOIN se_ruleset_st_ports
SELECT ipunique_g_dns.*,nice_se_ruleset_st_ports_qc.* FROM nice_se_ruleset_st_ports_qc 
INNER JOIN ipunique_g_dns ON nice_se_ruleset_st_ports_qc.ips=ipunique_g_dns.dst_ip;

#se_ruleset_st_ports RIGHT JOIN ipunique
SELECT countsrc,countdns,nice_se_ruleset_st_ports_qc.*,ipunique_g_dns.* FROM nice_se_ruleset_st_ports_qc RIGHT JOIN ipunique_g_dns 
ON nice_se_ruleset_st_ports_qc.ips=ipunique_g_dns.dst_ip
WHERE nice_se_ruleset_st_ports_qc.ips LIMIT 30000;
