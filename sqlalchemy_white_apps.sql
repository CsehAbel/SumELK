USE CSV_DB;

SHOW CREATE TABLE white_apps;

SELECT IPs as qc_ip,`APP ID` as qc_app_id,`Application Name` as qc_app_name FROM white_apps LIMIT 30000;

CREATE TABLE `white_apps` (
  `index` bigint DEFAULT NULL,
  `FQDN` text,
  `Ports` text,
  `IPs` text,
  `APP ID` text,
  `Protocol type port` text,
  `FQDNs` text,
  `Application Name` text,
  KEY `ix_white_apps_index` (`index`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE white_apps_trsfrm;
CREATE TABLE `white_apps_trsfrm` (
  `bp_FQDN` text,
  `bp_Ports` text,
  `bp_IPs` VARCHAR(30) NOT NULL,
  `QC_APP ID` text,
  `QC_Protocol type port` text,
  `QC_FQDNs` text,
  `QC_Application Name` text,
  PRIMARY KEY (`bp_IPs`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

SELECT * FROM white_apps LIMIT 60000;
SELECT * FROM white_apps WHERE (FQDN IS NOT NULL) LIMIT 60000;
SELECT * FROM white_apps  WHERE (dns2 IS NOT NULL) LIMIT 60000;
SELECT * FROM white_apps  WHERE (dns2 IS NOT NULL) OR (FQDN IS NOT NULL) LIMIT 60000;
SELECT * FROM white_apps  WHERE (dns2 IS NULL) AND (FQDN IS NULL) LIMIT 60000;

TRUNCATE TABLE white_apps_trsfrm;

INSERT INTO white_apps_trsfrm (`bp_IPs`,`bp_FQDN`,`bp_Ports`,`QC_APP ID`,`QC_Protocol type port`,`QC_FQDNs`,`QC_Application Name`)
    SELECT IPs,FQDN,Ports,`APP ID`,`Protocol type port`,FQDNs,`Application Name`
    FROM (SELECT * FROM white_apps WHERE IPs in (SELECT IPs FROM (SELECT COUNT(FQDN) as card,IPs FROM white_apps GROUP BY IPs HAVING card = 1) wa)) wa1;

SELECT * FROM white_apps_trsfrm LIMIT 5000;

SELECT IPs FROM (SELECT COUNT(FQDN) as card,IPs FROM white_apps GROUP BY IPs HAVING card = 1) wa LIMIT 30000;

SELECT * FROM white_apps WHERE IPs in (SELECT IPs FROM (SELECT COUNT(FQDN) as card,IPs FROM white_apps GROUP BY IPs HAVING card = 1) wa) LIMIT 30000;

SELECT * FROM 
(SELECT dst_ip, COUNT(src_ip) as c, GROUP_CONCAT(src_ip) FROM ip_unique GROUP BY dst_ip)  
AS iu 
INNER JOIN 
(SELECT `bp_IPs`,`bp_FQDN`,`bp_Ports`,`QC_APP ID`,`QC_Protocol type port`,`QC_FQDNs`,`QC_Application Name`
 FROM white_apps_trsfrm) wa1 ON iu.dst_ip = wa1.bp_IPs;
 
SELECT * FROM white_apps WHERE `APP ID` IS NULL;
SELECT * FROM white_apps WHERE `APP ID` IS NOT NULL LIMIT 30000;
SELECT * FROM white_apps LIMIT 30000;

SELECT `APP ID`,group_concat(FQDN),group_concat(`Protocol type port`),
group_concat(`Application Name`),group_concat(ip),group_concat(dns),group_concat(dns2) FROM white_apps 
WHERE IPs LIKE '139.23.160.218' GROUP BY IPs,`APP ID`;

SELECT `APP ID`,IPs FROM white_apps 
WHERE IPs LIKE '139.23.160.218' GROUP BY IPs,`APP ID`;

SELECT IPs,`APP ID`,group_concat(FQDN),group_concat(`Protocol type port`),group_concat(`Application Name`)
,group_concat(ip),group_concat(dns),group_concat(dns2) FROM white_apps 
 GROUP BY IPs,`APP ID` HAVING `APP ID` IS NULL LIMIT 60000;
 
 SELECT IPs,`APP ID`,group_concat(FQDN),group_concat(`Protocol type port`),group_concat(`Application Name`)
,group_concat(ip),group_concat(dns),group_concat(dns2) FROM white_apps 
 GROUP BY IPs,`APP ID` LIMIT 60000;
 
 SELECT IPs,`APP ID`,group_concat(FQDN),group_concat(`Protocol type port`),group_concat(`Application Name`)
,group_concat(ip),group_concat(dns),group_concat(dns2) FROM white_apps 
 GROUP BY IPs,`APP ID` HAVING `APP ID` IS NOT NULL LIMIT 60000;
 
 SELECT IPs as qc_ip,`APP ID` as qc_app_id,group_concat(DISTINCT(`Application Name`)) as qc_app_name FROM white_apps 
 GROUP BY IPs,`APP ID` HAVING `APP ID` IS NOT NULL LIMIT 20000;

