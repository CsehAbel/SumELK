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
    
SELECT COUNT(*) FROM ip;

#source ips fqdn correct
SELECT COUNT(*) FROM (SELECT * FROM ip_unique) as i INNER JOIN (SELECT * FROM sysdb) as s ON i.src_ip=s.ip
WHERE s.dns IS NOT NULL AND s.dns NOT LIKE '-';


SELECT dst_ip, src_ip, s.dns  FROM ip_unique LEFT JOIN (SELECT * FROM sysdb) as s ON ip_unique.src_ip=s.ip;

DROP TABLE hitsxsysdb;
CREATE TABLE hitsxsysdb
SELECT dst_ip, src_ip, s.dns FROM (SELECT *  FROM ip_unique) as i 
LEFT JOIN (SELECT * FROM sysdb) as s ON i.src_ip=s.ip;

#febr 6 - 1386, febr 28. 1486
#unique dst_ip = future number of rules
SELECT dst_ip, COUNT(src_ip), GROUP_CONCAT(src_ip) FROM ip_unique GROUP BY dst_ip LIMIT 50000;

SET group_concat_max_len=15000;

DROP TABLE hitsxse;
#455 number of correct fqdn matches number of source ips
CREATE TABLE hitsxse
SELECT dst_ip,GROUP_CONCAT(src_ip),GROUP_CONCAT(dns),COUNT(dns) as alldns,COUNT(CASE WHEN dns IS NULL OR dns LIKE '-' THEN NULL ELSE dns END) as validdns 
FROM hitsxsysdb GROUP BY dst_ip
HAVING validdns=alldns;




# WHERE dns IS NOT NULL AND dns NOT LIKE '-';

