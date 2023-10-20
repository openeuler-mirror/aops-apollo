use aops;

CREATE TABLE IF NOT EXISTS `cve`  (
  `cve_id` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `publish_time` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `severity` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `cvss_score` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `reboot` tinyint(1) NULL DEFAULT NULL,
  PRIMARY KEY (`cve_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

CREATE TABLE IF NOT EXISTS `vul_task` (
  `task_id` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `task_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `task_name` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `latest_execute_time` int(11) NULL DEFAULT NULL,
  `create_time` int(11) NULL DEFAULT NULL,
  `host_num` int(11) NULL DEFAULT NULL,
  `check_items` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `accepted` tinyint(1) NULL DEFAULT NULL,
  `username` varchar(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `takeover` tinyint(1) NULL DEFAULT 0,
  PRIMARY KEY (`task_id`) USING BTREE,
  INDEX `username`(`username`) USING BTREE,
  CONSTRAINT `vul_task_ibfk_1` FOREIGN KEY (`username`) REFERENCES `user` (`username`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

CREATE TABLE IF NOT EXISTS `cve_affected_pkgs`  (
  `cve_id` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `package` varchar(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `package_version` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `os_version` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `affected` int(11) NULL DEFAULT NULL,
  PRIMARY KEY (`cve_id`, `package`, `package_version`, `os_version`) USING BTREE,
  INDEX `ix_cve_affected_pkgs_os_version`(`os_version`) USING BTREE,
  CONSTRAINT `cve_affected_pkgs_ibfk_1` FOREIGN KEY (`cve_id`) REFERENCES `cve` (`cve_id`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

CREATE TABLE IF NOT EXISTS `cve_host_match`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cve_id` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `host_id` int(11) NULL DEFAULT NULL,
  `affected` tinyint(1) NULL DEFAULT NULL,
  `fixed` tinyint(1) NULL DEFAULT NULL,
  `support_way` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `fixed_way` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `hp_status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `installed_rpm` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `available_rpm` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `host_user` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `ix_cve_host_match_host_id`(`host_id`) USING BTREE,
  INDEX `ix_cve_host_match_cve_id`(`cve_id`) USING BTREE,
  INDEX `ix_cve_hsot_match_user`(`host_user`) USING BTREE,
  CONSTRAINT `cve_host_match_ibfk_1` FOREIGN KEY (`host_id`) REFERENCES `host` (`host_id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 2621 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

CREATE TABLE IF NOT EXISTS `parse_advisory_record` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `advisory_year` varchar(4) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `advisory_serial_number` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `download_status` tinyint(1) NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

CREATE TABLE IF NOT EXISTS `repo`  (
  `repo_id` int(11) NOT NULL AUTO_INCREMENT,
  `repo_name` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `repo_attr` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `repo_data` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `username` varchar(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  PRIMARY KEY (`repo_id`) USING BTREE,
  INDEX `username`(`username`) USING BTREE,
  CONSTRAINT `repo_ibfk_1` FOREIGN KEY (`username`) REFERENCES `user` (`username`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

CREATE TABLE IF NOT EXISTS `task_cve_host`  (
  `task_cve_host_id` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `task_id` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `cve_id` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `host_id` int(11) NOT NULL,
  `host_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `host_ip` varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `hotpatch` tinyint(4) NULL DEFAULT NULL,
  PRIMARY KEY (`task_cve_host_id`) USING BTREE,
  INDEX `task_cve_host_vul_fk1`(`task_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

CREATE TABLE IF NOT EXISTS `task_host_repo` (
  `task_id` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `host_id` int(11) NOT NULL,
  `host_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `host_ip` varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `repo_name` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  PRIMARY KEY (`task_id`, `host_id`) USING BTREE,
  CONSTRAINT `task_host_repo_ibfk_1` FOREIGN KEY (`task_id`) REFERENCES `vul_task` (`task_id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

CREATE TABLE IF NOT EXISTS `task_cve_host_rpm`  (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `task_cve_host_id` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `installed_rpm` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `available_rpm` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `fix_way` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `dnf_event_start` int(11) NULL DEFAULT NULL,
  `dnf_event_end` int(11) NULL DEFAULT NULL,
  `take_over_result` tinyint(1) NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 8 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

CREATE TABLE IF NOT EXISTS `task_rollback`(
  `id` int(11) NOT NULL,
  `host_id` int(11) NULL DEFAULT NULL,
  `task_id` int(11) NULL DEFAULT NULL,
  `fix_task_id` int(11) NULL DEFAULT NULL,
  `status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `host_ip` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `dnf_event_start` int(11) NULL DEFAULT NULL,
  `dnf_event_end` int(11) NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

CREATE PROCEDURE GET_CVE_LIST_PRO(IN username VARCHAR(20), IN search_key VARCHAR(100), IN severity VARCHAR(20), IN fixed TINYINT, IN affected TINYINT,IN order_by_filed VARCHAR(100),IN order_by VARCHAR(20),IN start_limt INT,IN end_limt INT)
BEGIN
		
		DROP TABLE IF EXISTS cve_host_user_count;
    SET @tmp_cve_host_count_sql = 'CREATE TEMPORARY TABLE cve_host_user_count SELECT
    cve_id,
    COUNT(host_id) AS host_num
    FROM
        cve_host_match FORCE INDEX (ix_cve_host_match_host_id)
    WHERE 1=1 ';

    IF search_key is not null and search_key !='' THEN
        SET @tmp_cve_host_count_sql = CONCAT(@tmp_cve_host_count_sql, ' AND LOCATE("', search_key, '", cve_id) > 0 ');
    END IF;
    IF fixed is not null THEN
        SET @tmp_cve_host_count_sql = CONCAT(@tmp_cve_host_count_sql, ' AND fixed = ', fixed, ' ');
    END IF;
    IF affected is not null THEN
        SET @tmp_cve_host_count_sql = CONCAT(@tmp_cve_host_count_sql, ' AND affected = ', affected, ' ');
    END IF;

    SET @tmp_cve_host_count_sql = CONCAT(@tmp_cve_host_count_sql, ' AND host_user = "', username, '" GROUP BY cve_id');
		
		prepare stmt from @tmp_cve_host_count_sql;
    EXECUTE stmt;
		DEALLOCATE PREPARE stmt;

    SET @cve_list_sql = 'SELECT
        cve_host_user_count.cve_id,
        cve.publish_time,
        cve_pkg.package,
        cve.severity,
        cve.cvss_score,
				cve_host_user_count.host_num
    FROM
        cve_host_user_count
        LEFT JOIN cve ON cve.cve_id = cve_host_user_count.cve_id
				LEFT JOIN (select DISTINCT cve_id,  GROUP_CONCAT(DISTINCT package SEPARATOR ",") AS package from cve_affected_pkgs group by cve_id) as cve_pkg ON cve_host_user_count.cve_id = cve_pkg.cve_id where 1=1 ';
				
		set @cve_list_page_count_sql='SELECT
        count(1) as total
    FROM
        cve_host_user_count
        LEFT JOIN cve ON cve.cve_id = cve_host_user_count.cve_id
        LEFT JOIN (select cve_id,package from cve_affected_pkgs GROUP BY cve_id,package) as cve_pkg ON cve_host_user_count.cve_id = cve_pkg.cve_id where 1=1 ';

    IF search_key IS NOT NULL and search_key !='' THEN
        SET @cve_list_sql = CONCAT(@cve_list_sql, 'AND ( LOCATE("', search_key, '", cve_pkg.package) > 0 ',' OR LOCATE("',search_key, '", cve_host_user_count.cve_id) > 0 ) ');
				SET @cve_list_page_count_sql = CONCAT(@cve_list_page_count_sql, 'AND ( LOCATE("', search_key, '", cve_pkg.package) > 0 ',' OR LOCATE("',search_key, '", cve_host_user_count.cve_id) > 0 ) ');
    END IF;
    IF severity IS NOT NULL and severity !='' THEN
        SET @cve_list_sql = CONCAT(@cve_list_sql, 'AND cve.severity IN (', severity, ') ');
				SET @cve_list_page_count_sql = CONCAT(@cve_list_page_count_sql, 'AND cve.severity IN (', severity, ') ');
    END IF;
		
-- 		IF order_by_filed IS NULL or order_by_filed ='' THEN
--         SET @order_by_filed = 'cve_host_user_count.host_num';
--     END IF;
-- 		 MySql 5.7 version '@' index error 

    SET @cve_list_sql = CONCAT(@cve_list_sql, ' ORDER BY ', order_by_filed ,' ', order_by);
		
		
		IF end_limt!=0 THEN
			SET @cve_list_sql = CONCAT(@cve_list_sql, ' limit ',start_limt ,' ,', end_limt);
		END IF;
		
		prepare stmt from @cve_list_sql;
    EXECUTE stmt;
		DEALLOCATE PREPARE stmt;
		
		prepare stmt from @cve_list_page_count_sql;
    EXECUTE stmt;
		DEALLOCATE PREPARE stmt;

END;

CREATE PROCEDURE GET_CVE_OVERVIEW_PRO(IN username VARCHAR(20))
BEGIN
		
		DROP TABLE IF EXISTS tmp_cve_overview;
    SET @tmp_cve_overview_sql = 'CREATE TEMPORARY TABLE tmp_cve_overview SELECT cve_id from cve_host_match where ';

    SET @tmp_cve_overview_sql = CONCAT(@tmp_cve_overview_sql, ' host_user = "', username, '" and  affected=1 and fixed=0 GROUP BY cve_id ');
		
		prepare stmt from @tmp_cve_overview_sql;
    EXECUTE stmt;
		DEALLOCATE PREPARE stmt;
		
		select CASE WHEN cve.severity is null THEN 'Unknown' ELSE cve.severity END as severity,count( CASE WHEN cve.severity is null THEN 'Unknown' ELSE cve.severity END ) as severity_count from tmp_cve_overview left join cve on cve.cve_id=tmp_cve_overview.cve_id GROUP BY cve.severity;

END;

CREATE TRIGGER tri_cvehost_match_user BEFORE INSERT ON cve_host_match
FOR EACH ROW
begin
	DECLARE host_user varchar(100);
	SELECT user into @host_user from host where host_id=new.host_id;
	set new.host_user=@host_user;
end;