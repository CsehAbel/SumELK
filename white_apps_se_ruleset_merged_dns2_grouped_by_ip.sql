#6588
CREATE TABLE white_apps_se_ruleset_merged_dns2_grouped_by_ip
SELECT ips,GROUP_CONCAT(DISTINCT(app_id)) as g_app_id,COUNT(*) as cardinality,
GROUP_CONCAT(DISTINCT(ip)) as g_s_ip,
GROUP_CONCAT(DISTINCT(c)) as g_s_c,
GROUP_CONCAT(DISTINCT(l)) as g_s_l,
GROUP_CONCAT(DISTINCT(sys_type)) as g_s_sys_type,
GROUP_CONCAT(DISTINCT(corpflag)) as g_s_corpflag,
GROUP_CONCAT(DISTINCT(info_extra)) as g_s_info_extra,
GROUP_CONCAT(DISTINCT(info)) as g_s_info,
GROUP_CONCAT(DISTINCT(hostname)) as g_s_hostname,
GROUP_CONCAT(DISTINCT(domain)) as g_s_domain,
GROUP_CONCAT(DISTINCT(region)) as g_s_region,
GROUP_CONCAT(DISTINCT(snic_comment)) as g_s_snic_comment,
GROUP_CONCAT(DISTINCT(ip_cidr)) as g_s_ip_cidr,
GROUP_CONCAT(DISTINCT(vpn_name)) as g_s_vpn_name,
GROUP_CONCAT(DISTINCT(change_type)) as g_change_type,
GROUP_CONCAT(DISTINCT(tufin_id)) as g_tufin_id,
GROUP_CONCAT(DISTINCT(source)) as g_source,
GROUP_CONCAT(DISTINCT(dest_info)) as g_dest_info,
GROUP_CONCAT(DISTINCT(port)) as g_port,
GROUP_CONCAT(DISTINCT(tsa_expiration_date)) as g_tsa_expiration_date,
GROUP_CONCAT(DISTINCT(application_requestor)) as g_application_requestor,
GROUP_CONCAT(DISTINCT(comment)) as g_comment,
GROUP_CONCAT(DISTINCT(dns2)) as g_dns2
FROM white_apps_se_ruleset_merged_dns2 
WHERE dns2 NOT LIKE '-' AND dns2 IS NOT NULL GROUP BY ips;