USE CSV_DB;
LOAD DATA LOCAL INFILE "C:/ProgramData/MySQL/MySQL Server 8.0/data/Uploads/ip_dump.csv" INTO TABLE ip FIELDS TERMINATED BY ',' ENCLOSED BY '';

SELECT COUNT(*) FROM ip;
SELECT * FROM ip WHERE id = 1;