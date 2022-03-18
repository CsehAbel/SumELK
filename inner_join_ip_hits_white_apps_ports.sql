USE CSV_DB;
USE CSV_DB;

CREATE TABLE `ip_unique` (
  `src_ip` VARCHAR(15) NOT NULL,
  `dst_ip` VARCHAR(15) NOT NULL,
  PRIMARY KEY (`src_ip`,`dst_ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

TRUNCATE TABLE ip_unique;

INSERT IGNORE INTO ip_unique (`src_ip`,`dst_ip`)
    SELECT ip.src_ip,ip.dst_ip
    FROM ip;

#17182
SELECT src_ip FROM ip_unique GROUP BY src_ip LIMIT 30000; 

#2658
SELECT COUNT(*) FROM src_dns WHERE dns IS NOT NULL;
#17182
SELECT COUNT(*) FROM src_dns;

#22936 ip_unique innerjoin src_dns
SELECT COUNT(*) FROM (SELECT * FROM src_dns WHERE dns IS NOT NULL) as src 
INNER JOIN (SELECT * FROM ip_unique) as iu ON src.src_ip=iu.src_ip;

#38693 ip_unique innerjoin sysdb
SELECT COUNT(*) FROM (SELECT * FROM ip_unique) as i INNER JOIN 
(SELECT * FROM sysdb WHERE dns IS NOT NULL AND dns NOT LIKE '-') as s ON i.src_ip=s.ip
;

 #161 540
 SELECT COUNT(*) FROM ip_unique;

#163 091
SELECT COUNT(*) FROM (SELECT * FROM ip_unique) as i LEFT JOIN (SELECT * FROM sysdb
 WHERE dns IS NOT NULL AND dns NOT LIKE '-') as s
 ON i.src_ip=s.ip LEFT JOIN (SELECT * FROM src_dns WHERE dns IS NOT NULL) as src 
 ON i.src_ip=src.src_ip;
 
 #163 974
 DROP TABLE ipunique_ljoin_sysdb_srcdns;
 CREATE TABLE ipunique_ljoin_sysdb_srcdns
 SELECT i.src_ip,i.dst_ip,s.dns as s_dns,src.dns as src_dns FROM 
 (SELECT * FROM ip_unique) as i 
 LEFT JOIN 
 (SELECT * FROM sysdb) as s ON i.src_ip=s.ip 
 LEFT JOIN
 (SELECT * FROM src_dns ) as src ON i.src_ip=src.src_ip;
 
DROP TABLE ipunique_dns;
CREATE TABLE ipunique_dns 
SELECT src_ip,dst_ip,(CASE WHEN src_dns IS NOT NULL THEN src_dns ELSE 
(CASE WHEN s_dns LIKE '-' THEN NULL ELSE s_dns END) END) as dns 
FROM ipunique_ljoin_sysdb_srcdns;
 
SET group_concat_max_len=150000; 
 
DROP TABLE ipunique_g_dns;
#519 number of not null dns equals number of source ips
CREATE TABLE ipunique_g_dns_valid
SELECT dst_ip,
GROUP_CONCAT(DISTINCT(src_ip)) as g_src_ip,
GROUP_CONCAT(DISTINCT(dns)) as g_dns,
COUNT(dns) as countdns,
#only counts not null
COUNT(src_ip) as countsrc
FROM ipunique_dns GROUP BY dst_ip
HAVING countsrc=countdns;

SELECT * FROM ipunique_g_dns_valid;

DROP TABLE ipunique_g_dns;
CREATE TABLE ipunique_g_dns
SELECT dst_ip,

GROUP_CONCAT(DISTINCT(dns)) as g_dns,
COUNT(dns) as countdns,
#only counts not null
COUNT(src_ip) as countsrc
FROM ipunique_dns GROUP BY dst_ip;

SELECT * FROM ipunique_g_dns ORDER BY countsrc DESC;

#WHERE dns IS NOT NULL AND dns NOT LIKE '-';
SELECT * FROM nice_se_ruleset_st_ports_qc;

#ipunique INNER JOIN se_ruleset_st_ports
SELECT ipunique_g_dns.*,nice_se_ruleset_st_ports_qc.* FROM nice_se_ruleset_st_ports_qc 
INNER JOIN ipunique_g_dns ON nice_se_ruleset_st_ports_qc.ips=ipunique_g_dns.dst_ip;

#se_ruleset_st_ports RIGHT JOIN ipunique
SELECT * FROM nice_se_ruleset_st_ports_qc RIGHT JOIN ipunique_g_dns 
ON nice_se_ruleset_st_ports_qc.ips=ipunique_g_dns.dst_ip
WHERE nice_se_ruleset_st_ports_qc.ips;
