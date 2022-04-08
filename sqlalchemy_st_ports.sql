USE CSV_DB;
#106984
SELECT COUNT(*) FROM st_ports LIMIT 30000;

SELECT rule_name FROM st_ports GROUP BY rule_name;

#st_ports group by dest_ip
SELECT st_dest_ip,GROUP_CONCAT(st_port),GROUP_CONCAT(st_serv_name),GROUP_CONCAT(rule_name),GROUP_CONCAT(rule_order),GROUP_CONCAT(rule_number) FROM st_ports GROUP BY st_dest_ip LIMIT 30000;


SELECT st_dest_ip FROM st_ports GROUP BY st_dest_ip LIMIT 30000;
SELECT rule_name FROM st_ports GROUP BY rule_name LIMIT 30000;
#st_ports group by dest_ip,rule_name
SELECT st_dest_ip,rule_name,GROUP_CONCAT(st_port),GROUP_CONCAT(st_serv_name),GROUP_CONCAT(rule_order),GROUP_CONCAT(rule_number) FROM st_ports GROUP BY st_dest_ip,rule_name LIMIT 30000;