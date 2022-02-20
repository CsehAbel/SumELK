USE CSV_DB;

SELECT * FROM st_ports;

SELECT rule_name FROM st_ports GROUP BY rule_name;

SELECT st_port, GROUP_CONCAT(st_dest_ip), GROUP_CONCAT(st_serv_name),GROUP_CONCAT(rule_name),GROUP_CONCAT(rule_order),GROUP_CONCAT(rule_number)   FROM st_ports GROUP BY st_port LIMIT 10000;