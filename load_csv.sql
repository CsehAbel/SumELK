USE CSV_DB;

SHOW CREATE TABLE ip;

CREATE TABLE `ip` (
  `id` int NOT NULL,
  `src_ip` VARCHAR(15) NOT NULL,
  `dst_ip` VARCHAR(15) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

TRUNCATE TABLE ip;

SET GLOBAL local_infile=1;

LOAD DATA LOCAL INFILE 'C:/ProgramData/MySQL/MySQL Server 8.0/Uploads/df_hits.csv' IGNORE INTO TABLE ip
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
IGNORE 1 LINES;

#INNER JOIN
SELECT * FROM nice_se_ruleset_st_ports_qc INNER JOIN hitsxse ON nice_se_ruleset_st_ports_qc.ips=hitsxse.dst_ip;

#LEFT JOIN
SELECT * FROM nice_se_ruleset_st_ports_qc INNER JOIN hitsxse ON nice_se_ruleset_st_ports_qc.ips=hitsxse.dst_ip;
