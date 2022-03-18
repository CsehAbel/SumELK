SELECT * FROM white_apps_dns WHERE dns is NULL LIMIT 30000;
# 2783
SELECT * FROM white_apps_dns WHERE dns is NOT NULL LIMIT 30000;
# 19304
SELECT COUNT(*) FROM white_apps_dns;

SELECT COUNT(*) FROM ip_unique;
SELECT * FROM ip_unique;
SELECT src_ip FROM ip_unique GROUP BY src_ip LIMIT 20000;
SELECT COUNT(*) FROM (SELECT * FROM ip_unique GROUP BY src_ip) as s;

SELECT * FROM src_dns WHERE dns is NULL LIMIT 30000;
SELECT * FROM src_dns WHERE dns is NOT NULL LIMIT 30000;