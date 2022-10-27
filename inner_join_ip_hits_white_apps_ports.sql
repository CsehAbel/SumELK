USE CSV_DB;

#239786
SELECT COUNT(*) FROM ip;
SELECT * FROM ip;

#Filter out EAGLE
#Filter only all_red_networks_systems
SELECT COUNT(*) FROM systems;
SELECT COUNT(*) FROM eagle; 
 
SET SESSION group_concat_max_len=1500000; 
 
#show processlist;
#kill 55;

DROP TABLE IF EXISTS ip_filtered;
CREATE TABLE IF NOT EXISTS ip_filtered
SELECT dst_ip,
GROUP_CONCAT(DISTINCT(src_ip)) as s_g_src_ip,
COUNT(src_ip) as countsrc
FROM (SELECT * FROM ip) as i 
LEFT JOIN (SELECT ip as dip FROM eagle) as e
ON i.dst_ip=e.dip 
LEFT JOIN (SELECT `0` as sip FROM systems) as o 
ON i.src_ip=o.sip 
WHERE e.dip IS NULL AND o.sip IS NOT NULL 
GROUP BY dst_ip
;

#ip INNER JOIN st_ports
SELECT ip_filtered.*,st_ports.* FROM st_ports
INNER JOIN ip_filtered ON st_ports.st_dest_ip=ip_filtered.dst_ip ORDER BY countsrc DESC;

#ip INNER JOIN ruleset
SELECT ip_filtered.*,ruleset.* FROM ruleset
INNER JOIN ip_filtered ON ruleset.ip=ip_filtered.dst_ip ORDER BY countsrc DESC;

SELECT * FROM csv_db.ruleset_st_ports;
#ip INNER JOIN ruleset_st_ports
SELECT ip_filtered.*,ruleset_st_ports.* FROM ruleset_st_ports
INNER JOIN ip_filtered ON ruleset_st_ports.ip=ip_filtered.dst_ip ORDER BY countsrc DESC;

#ip INNER JOIN ruleset_not_in_st_ports
SELECT ip_filtered.*,ruleset_not_in_st_ports.* FROM ruleset_not_in_st_ports
INNER JOIN ip_filtered ON ruleset_not_in_st_ports.ip=ip_filtered.dst_ip ORDER BY countsrc DESC;

#ip INNER JOIN not_in_ruleset_but_in_st_ports
SELECT ip_filtered.*,not_in_ruleset_but_in_st_ports.* FROM not_in_ruleset_but_in_st_ports
INNER JOIN ip_filtered ON not_in_ruleset_but_in_st_ports.ip=ip_filtered.dst_ip ORDER BY countsrc DESC;

#ip INNER JOIN ruleset_st_ports

#WHERE dst_ip LIKE "139.23.230.92" LIMIT 30000;

#ruleset_st_ports RIGHT JOIN ip

