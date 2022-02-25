USE CSV_DB;

SHOW TABLES;

#se_ruleset left join with sysdb
SELECT * FROM se_ruleset_fqdn_error;

#se_ruleset left join with sysdb
SELECT * FROM white_apps_se_ruleset WHERE ip is NULL LIMIT 20000;

