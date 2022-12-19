USE DARWIN_DB;

DROP TABLE `ip_unique` IF EXISTS;

#SHOW PROCESSLIST;
#python appends the fqdns to this table, select only one fqdn per src_ip
SELECT COUNT(*) FROM src_dns WHERE dns IS NOT NULL;
SELECT COUNT(*) FROM
(SELECT src_ip,MAX(dns) as dns FROM src_dns WHERE dns IS NOT NULL GROUP BY src_ip) as sd;

#ip_unique left join src_dns
SELECT iu.*,src.dns FROM (SELECT * FROM ip) as iu
LEFT JOIN (SELECT * FROM src_dns WHERE dns IS NOT NULL) as src  ON src.src_ip=iu.src_ip;

#ip_unique left join sysdb
SELECT iu.*,s.dns FROM (SELECT * FROM ip) as iu LEFT JOIN
(SELECT * FROM sysdb WHERE dns IS NOT NULL AND dns NOT LIKE '-') as s ON iu.src_ip=s.ip;

 #253767
 SELECT COUNT(*) FROM ipunique_ljoin_sysdb_srcdns;
 DROP TABLE ipunique_ljoin_sysdb_srcdns IF EXISTS;
 CREATE TABLE ipunique_ljoin_sysdb_srcdns
 SELECT iu.*,CASE WHEN src.dns IS NOT NULL THEN src.dns ELSE s.dns END as dns FROM 
 (SELECT * FROM ip) as iu
LEFT JOIN (SELECT * FROM src_dns WHERE dns IS NOT NULL) as src 
 ON iu.src_ip=src.src_ip
 LEFT JOIN (SELECT * FROM sysdb
 WHERE dns IS NOT NULL AND dns NOT LIKE '-') as s
 ON iu.src_ip=s.ip;
 
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
FROM (SELECT * FROM ipunique_ljoin_sysdb_srcdns) as i
LEFT JOIN (SELECT ip as dip FROM eagle) as e
ON i.dst_ip=e.dip 
LEFT JOIN (SELECT `0` as sip FROM systems) as o 
ON i.src_ip=o.sip 
WHERE e.dip IS NULL AND o.sip IS NOT NULL 
GROUP BY dst_ip
#HAVING countsrc=countdns
;

SELECT * FROM nice_dw_ruleset_st_ports;

#ipunique INNER JOIN se_ruleset_st_ports

SELECT ipunique_g_dns.*,nice_se_ruleset_st_ports_qc.* FROM nice_se_ruleset_st_ports_qc 
INNER JOIN ipunique_g_dns ON nice_se_ruleset_st_ports_qc.ips=ipunique_g_dns.dst_ip ORDER BY countsrc DESC;

SELECT ipunique_g_dns.*,nice_se_ruleset_st_ports_qc.* FROM nice_se_ruleset_st_ports_qc 
INNER JOIN ipunique_g_dns ON nice_se_ruleset_st_ports_qc.ips=ipunique_g_dns.dst_ip WHERE dst_ip LIKE "139.23.230.92" LIMIT 30000;