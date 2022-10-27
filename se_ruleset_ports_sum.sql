USE CSV_DB;

SELECT ip,GROUP_CONCAT(DISTINCT(app_id)),GROUP_CONCAT(DISTINCT(app_name)),GROUP_CONCAT(DISTINCT(tsa)),GROUP_CONCAT(DISTINCT(fqdns)) FROM ruleset GROUP BY ip;

SELECT * FROM csv_db.ruleset_st_ports;
DROP TABLE IF EXISTS ruleset_st_ports;
CREATE TABLE IF NOT EXISTS ruleset_st_ports
SELECT * FROM 
(SELECT ip,
GROUP_CONCAT(DISTINCT(app_id)),
GROUP_CONCAT(DISTINCT(app_name)),
GROUP_CONCAT(DISTINCT(tsa)),
GROUP_CONCAT(DISTINCT(fqdns)) 
FROM ruleset GROUP BY ip) as wa
 INNER JOIN
(SELECT st_dest_ip,
GROUP_CONCAT(DISTINCT(rule_name)) as g_rule_name,
GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip)
as ports ON wa.ip = ports.st_dest_ip;

SELECT * FROM ruleset_not_in_st_ports;
DROP TABLE IF EXISTS ruleset_not_in_st_ports;
CREATE TABLE IF NOT EXISTS ruleset_not_in_st_ports
SELECT * FROM 
(SELECT ip,
GROUP_CONCAT(DISTINCT(`start`)),
GROUP_CONCAT(DISTINCT(`end`)),
GROUP_CONCAT(DISTINCT(`cidr`)),
GROUP_CONCAT(DISTINCT(app_id)),
GROUP_CONCAT(DISTINCT(app_name)),
GROUP_CONCAT(DISTINCT(tsa)),
GROUP_CONCAT(DISTINCT(fqdns)) 
FROM ruleset GROUP BY ip) as wa
 LEFT JOIN
(SELECT st_dest_ip,
GROUP_CONCAT(DISTINCT(rule_name)) as g_rule_name,
GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip)
as ports ON wa.ip = ports.st_dest_ip WHERE ports.st_dest_ip IS NULL;

SELECT * FROM not_in_ruleset_but_in_st_ports;
DROP TABLE IF EXISTS not_in_ruleset_but_in_st_ports;
CREATE TABLE IF NOT EXISTS not_in_ruleset_but_in_st_ports
SELECT * FROM 
(SELECT ip,
GROUP_CONCAT(DISTINCT(`start`)),
GROUP_CONCAT(DISTINCT(`end`)),
GROUP_CONCAT(DISTINCT(`cidr`)),
GROUP_CONCAT(DISTINCT(app_id)),
GROUP_CONCAT(DISTINCT(app_name)),
GROUP_CONCAT(DISTINCT(tsa)),
GROUP_CONCAT(DISTINCT(fqdns)) 
FROM ruleset GROUP BY ip) as wa
 RIGHT JOIN
(SELECT st_dest_ip,
GROUP_CONCAT(DISTINCT(rule_name)) as g_rule_name,
GROUP_CONCAT(DISTINCT(st_port)) as g_st_port,
GROUP_CONCAT(DISTINCT(rule_number)) as g_rule_number
FROM st_ports GROUP BY st_dest_ip)
as ports ON wa.ip = ports.st_dest_ip WHERE wa.ip IS NULL;