USE CSV_DB;

SHOW CREATE TABLE white_apps;

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

SELECT * FROM white_apps LIMIT 6000;

TRUNCATE TABLE white_apps_trsfrm;

INSERT INTO white_apps_trsfrm (`bp_IPs`,`bp_FQDN`,`bp_Ports`,`QC_APP ID`,`QC_Protocol type port`,`QC_FQDNs`,`QC_Application Name`)
    SELECT IPs,FQDN,Ports,`APP ID`,`Protocol type port`,FQDNs,`Application Name`
    FROM (SELECT * FROM white_apps WHERE IPs in (SELECT IPs FROM (SELECT COUNT(FQDN) as card,IPs FROM white_apps GROUP BY IPs HAVING card = 1) wa)) wa1;

SELECT * FROM white_apps_trsfrm LIMIT 5000;

SELECT * FROM white_apps WHERE IPs LIKE '139.23.160.218';

SELECT IPs FROM (SELECT COUNT(FQDN) as card,IPs FROM white_apps GROUP BY IPs HAVING card = 1) wa LIMIT 3000;

SELECT * FROM white_apps WHERE IPs in (SELECT IPs FROM (SELECT COUNT(FQDN) as card,IPs FROM white_apps GROUP BY IPs HAVING card = 1) wa) LIMIT 3000;

SELECT * FROM 
(SELECT dst_ip, COUNT(src_ip) as c, GROUP_CONCAT(src_ip) FROM ip_unique GROUP BY dst_ip)  
AS iu 
INNER JOIN 
(SELECT `bp_IPs`,`bp_FQDN`,`bp_Ports`,`QC_APP ID`,`QC_Protocol type port`,`QC_FQDNs`,`QC_Application Name`
 FROM white_apps_trsfrm) wa1 ON iu.dst_ip = wa1.bp_IPs;
