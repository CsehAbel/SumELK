USE CSV_DB;

SHOW CREATE TABLE ip;

CREATE TABLE `ip` (
  `id` int NOT NULL,
  `src_ip` VARCHAR(15) NOT NULL,
  `dst_ip` VARCHAR(15) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

SELECT id, dst_ip, GROUP_CONCAT(src_ip) FROM ip GROUP BY dst_ip;

CREATE TABLE `ip_unique` (
  `src_ip` VARCHAR(15) NOT NULL,
  `dst_ip` VARCHAR(15) NOT NULL,
  PRIMARY KEY (`src_ip`,`dst_ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT IGNORE INTO ip_unique (`src_ip`,`dst_ip`)
    SELECT ip.src_ip,ip.dst_ip
    FROM ip;
    
SELECT COUNT(*) FROM ip_unique;
SELECT COUNT(*) FROM ip;

SELECT dst_ip, COUNT(src_ip), GROUP_CONCAT(src_ip) FROM ip_unique GROUP BY dst_ip;
