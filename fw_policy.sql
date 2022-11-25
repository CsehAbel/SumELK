SELECT * FROM csv_db.`fwpolicy` WHERE dest_ip_type LIKE 'range';
SELECT COUNT(*) FROM csv_db.`fwpolicy`;
SELECT COUNT(*) FROM csv_db.ruleset;
SELECT * FROM csv_db.ruleset WHERE tsa<"2022.11.15";
SELECT * FROM csv_db.`fwpolicy`;

# \begin{comparison}
# JOIN fwpolicy and ruleset find records which match, find records which are:
# \begin{itemize}
# I. only in fwpolicy but not in ruleset
# II. only in ruleset but not fwpolicy
# \end{itemize}

# \begin{id clashing}
# while trying to display the joined ruleset,fwpolicy we get Error Code: 1060. Duplicate column name 'id'
# the clashing of r.id, f.id is solved by using aliases rid, fid in the outer select
# we cant use r.*,f.* to select the rest of the columns becuase there would be name clashing of r.id and f.id
# we need to include in the outer select the column names  other than r.id,f.id

CREATE TABLE columns_except_id_r
SELECT `COLUMN_NAME` FROM `information_schema`.`COLUMNS` WHERE (`TABLE_SCHEMA` = 'csv_db') AND (`TABLE_NAME` = 'ruleset') 
AND (`COLUMN_NAME` NOT LIKE 'id');

CREATE TABLE columns_except_id_f
SELECT `COLUMN_NAME` FROM `information_schema`.`COLUMNS` WHERE (`TABLE_SCHEMA` = 'csv_db') AND (`TABLE_NAME` = 'fwpolicy') 
AND (`COLUMN_NAME` NOT LIKE 'id');

SELECT GROUP_CONCAT(`COLUMN_NAME`) FROM columns_except_id_r;
SELECT GROUP_CONCAT(`COLUMN_NAME`) FROM columns_except_id_f;

DROP TABLE IF EXISTS start_matches;
CREATE TABLE start_matches
SELECT r.id as rid,start,end,start_int,end_int,cidr,fqdns,tsa,app_name,app_id,
f.id as fid,dest_ip_start,dest_ip_end,dest_ip_cidr,dest_ip_type,dest_ip_start_int,dest_ip_end_int,json_services,rule_name,rule_number
 FROM (SELECT * FROM csv_db.ruleset) as r 
INNER JOIN (SELECT * FROM csv_db.`fwpolicy`) as f ON r.start_int=f.dest_ip_start_int;

# \end{id clashing}

SELECT * FROM start_matches;

CREATE TABLE start_and_end_matches
SELECT r.id as rid,start,end,start_int,end_int,cidr,fqdns,tsa,app_name,app_id,
f.id as fid,dest_ip_start,dest_ip_end,dest_ip_cidr,dest_ip_type,dest_ip_start_int,dest_ip_end_int,json_services,rule_name,rule_number
 FROM (SELECT * FROM csv_db.ruleset) as r 
INNER JOIN (SELECT * FROM csv_db.`fwpolicy`) as f ON r.start_int=f.dest_ip_start_int AND r.end_int=f.dest_ip_end_int;


#\begin{SELECT rid,fid which are not in the inner join}
SELECT COUNT(*) FROM csv_db.`start_and_end_matches`;
SELECT fid FROM csv_db.start_and_end_matches GROUP BY fid;
#everything thats in the fwpolicy should be im the inner join
#currently out of 2175 records
SELECT COUNT(*) FROM csv_db.`fwpolicy`;
#613 is not in the inner join
SELECT COUNT(*) FROM csv_db.fwpolicy as f WHERE f.id NOT IN (SELECT fid FROM csv_db.start_and_end_matches GROUP BY fid);


#everything thats in the ruleset should be im the inner join
#currently out of 2408 records
SELECT COUNT(*) FROM csv_db.`ruleset`;
#347 is not in the inner join
SELECT * FROM csv_db.ruleset as r WHERE r.id NOT IN (SELECT rid FROM csv_db.start_and_end_matches GROUP BY rid);
#\end{SELECT rid,fid which are not in the inner join}


