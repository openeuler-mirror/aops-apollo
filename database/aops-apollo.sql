CREATE DATABASE IF NOT EXISTS aops DEFAULT CHARACTER SET utf8mb4 DEFAULT COLLATE utf8mb4_bin;
use aops;

-- ----------------------------
-- Table structure for cve
-- ----------------------------
CREATE TABLE IF NOT EXISTS `cve`  (
  `cve_id` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `publish_time` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `severity` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `cvss_score` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `reboot` tinyint(1) NULL DEFAULT NULL,
  PRIMARY KEY (`cve_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for vul_task
-- ----------------------------
CREATE TABLE IF NOT EXISTS `vul_task` (
  `task_id` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `task_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `description` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `task_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `latest_execute_time` int(11) NULL DEFAULT NULL,
  `create_time` int(11) NULL DEFAULT NULL,
  `host_num` int(11) NULL DEFAULT NULL,
  `check_items` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `accepted` tinyint(1) NULL DEFAULT NULL,
  `takeover` tinyint(1) NULL DEFAULT 0,
  `fix_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `cluster_id` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `username` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  PRIMARY KEY (`task_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for cve_affected_pkgs
-- ----------------------------
CREATE TABLE IF NOT EXISTS `cve_affected_pkgs`  (
  `cve_id` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `package` varchar(40) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `package_version` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `os_version` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `affected` int(11) NULL DEFAULT NULL,
  PRIMARY KEY (`cve_id`, `package`, `package_version`, `os_version`) USING BTREE,
  INDEX `ix_cve_affected_pkgs_os_version`(`os_version`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for cve_host_match
-- ----------------------------
CREATE TABLE IF NOT EXISTS `cve_host_match`  (
  `id` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `cve_id` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `host_id` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `affected` tinyint(1) NULL DEFAULT NULL,
  `fixed` tinyint(1) NULL DEFAULT NULL,
  `support_way` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `fixed_way` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `hp_status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `installed_rpm` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `available_rpm` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `cluster_id` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `ix_cve_host_match_host_id`(`host_id`) USING BTREE,
  INDEX `ix_cve_host_match_cve_id`(`cve_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for parse_advisory_record
-- ----------------------------
CREATE TABLE IF NOT EXISTS `parse_advisory_record` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `advisory_year` varchar(4) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `advisory_serial_number` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `download_status` tinyint(1) NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for repo
-- ----------------------------
CREATE TABLE IF NOT EXISTS `repo`  (
  `repo_id` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `repo_name` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `repo_attr` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `repo_data` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `cluster_id` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  PRIMARY KEY (`repo_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for hotpatch_remove_task
-- ----------------------------
CREATE TABLE IF NOT EXISTS `hotpatch_remove_task`  (
  `task_cve_host_id` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `task_id` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `cve_id` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `host_id` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `host_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `host_ip` varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  PRIMARY KEY (`task_cve_host_id`) USING BTREE,
  INDEX `task_cve_host_vul_fk1`(`task_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;


-- ----------------------------
-- Table structure for task_host_repo
-- ----------------------------
CREATE TABLE IF NOT EXISTS `task_host_repo` (
  `task_id` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `host_id` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `host_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `host_ip` varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `repo_id` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  PRIMARY KEY (`task_id`, `host_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for cve_fix_task
-- ----------------------------
CREATE TABLE IF NOT EXISTS `cve_fix_task`  (
  `id` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `task_id` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `host_id` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `host_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `host_ip` varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `cves` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `installed_rpm` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `available_rpm` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `fix_way` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `take_over_result` tinyint(1) NULL DEFAULT NULL,
  `dnf_event_start` int(11) NULL DEFAULT NULL,
  `dnf_event_end` int(11) NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for cve_rollback_task
-- ----------------------------
CREATE TABLE IF NOT EXISTS `cve_rollback_task`(
  `id` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `host_id` varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `task_id` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `fix_task_id` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `host_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `host_ip` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `cves` text CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `installed_rpm` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `target_rpm` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL,
  `rollback_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `dnf_event_start` int(11) NULL DEFAULT NULL,
  `dnf_event_end` int(11) NULL DEFAULT NULL,

  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;

-- ----------------------------
-- Procedure structure for GET_CVE_LIST_PRO
-- ----------------------------
DROP PROCEDURE IF EXISTS `GET_CVE_LIST_PRO`;
CREATE DEFINER=`root`@`%` PROCEDURE `GET_CVE_LIST_PRO`(
    IN search_key VARCHAR(100), 
    IN severity VARCHAR(200), 
    IN fixed TINYINT, 
    IN affected TINYINT,
    IN order_by_field VARCHAR(100),
    IN order_by VARCHAR(20),
    IN start_limit INT,
    IN limit_size INT,
    IN host_list VARCHAR(255)
)
BEGIN
		
		DROP TABLE IF EXISTS cve_host_user_count;
    SET @tmp_cve_host_count_sql = 'CREATE TEMPORARY TABLE cve_host_user_count SELECT
    cve_id,
    COUNT(DISTINCT host_id) AS host_num
    FROM
        cve_host_match FORCE INDEX (ix_cve_host_match_host_id)
    WHERE 1=1 ';

    IF fixed is not null THEN
        SET @tmp_cve_host_count_sql = CONCAT(@tmp_cve_host_count_sql, ' AND fixed = ', fixed, ' ');
    END IF;
    IF affected is not null THEN
        SET @tmp_cve_host_count_sql = CONCAT(@tmp_cve_host_count_sql, ' AND affected = ', affected, ' ');
    END IF;

    IF host_list IS NOT NULL AND host_list != '' THEN
        SET @tmp_cve_host_count_sql = CONCAT(@tmp_cve_host_count_sql, ' AND cve_host_match.host_id IN (', host_list, ') ');
    ELSE
        -- If host_list is empty, the query should not return any data. 
        -- We do this by adding a condition that is always false.
        SET @tmp_cve_host_count_sql = CONCAT(@tmp_cve_host_count_sql, ' AND 0 = 1 ');
    END IF;

    SET @tmp_cve_host_count_sql = CONCAT(@tmp_cve_host_count_sql,'GROUP BY cve_id');
		
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
        LEFT JOIN (SELECT DISTINCT cve_id, GROUP_CONCAT(DISTINCT package SEPARATOR ",") AS package FROM cve_affected_pkgs GROUP BY cve_id) AS cve_pkg ON cve_host_user_count.cve_id = cve_pkg.cve_id WHERE 1=1 ';
				
    SET @cve_list_page_count_sql='SELECT
        COUNT(1) AS total
    FROM
        cve_host_user_count
        LEFT JOIN cve ON cve.cve_id = cve_host_user_count.cve_id
        LEFT JOIN (SELECT cve_id, package FROM cve_affected_pkgs GROUP BY cve_id, package) AS cve_pkg ON cve_host_user_count.cve_id = cve_pkg.cve_id WHERE 1=1 ';

    IF search_key IS NOT NULL AND search_key != '' THEN
        SET @cve_list_sql = CONCAT(@cve_list_sql, 'AND (LOCATE("', search_key, '", cve_pkg.package) > 0 OR LOCATE("', search_key, '", cve_host_user_count.cve_id) > 0) ');
        SET @cve_list_page_count_sql = CONCAT(@cve_list_page_count_sql, 'AND (LOCATE("', search_key, '", cve_pkg.package) > 0 OR LOCATE("', search_key, '", cve_host_user_count.cve_id) > 0) ');
    END IF;

    IF severity IS NOT NULL AND severity != '' THEN
        SET @cve_list_sql = CONCAT(@cve_list_sql, 'AND cve.severity IN (', severity, ') ');
        SET @cve_list_page_count_sql = CONCAT(@cve_list_page_count_sql, 'AND cve.severity IN (', severity, ') ');
    END IF;
-- 		IF order_by_filed IS NULL or order_by_filed ='' THEN
--         SET @order_by_filed = 'cve_host_user_count.host_num';
--     END IF;
-- 		 MySql 5.7 version '@' index error 
    SET @cve_list_sql = CONCAT('SELECT s.* FROM ( ', @cve_list_sql, ' ) AS s ORDER BY ', order_by_field, ' ', order_by);

    IF limit_size != 0 THEN
        SET @cve_list_sql = CONCAT(@cve_list_sql, ' LIMIT ', start_limit, ' ,', limit_size);
    END IF;

    PREPARE stmt FROM @cve_list_sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;

    PREPARE stmt FROM @cve_list_page_count_sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;

END;

-- ----------------------------
-- Procedure structure for GET_CVE_OVERVIEW_PRO
-- ----------------------------

DROP PROCEDURE IF EXISTS `GET_CVE_OVERVIEW_PRO`;
CREATE PROCEDURE `GET_CVE_OVERVIEW_PRO`(IN host_list VARCHAR(255))
BEGIN
    DROP TABLE IF EXISTS tmp_cve_overview;
    SET @tmp_cve_overview_sql = 'CREATE TEMPORARY TABLE tmp_cve_overview SELECT cve_id FROM cve_host_match WHERE ';

    SET @tmp_cve_overview_sql = CONCAT(@tmp_cve_overview_sql, 'affected = 1 AND fixed = 0');

    IF host_list IS NOT NULL THEN
        SET @tmp_cve_overview_sql = CONCAT(@tmp_cve_overview_sql, ' AND host_id IN (', host_list, ')');
		ELSE
        -- If host_list is empty, the query should not return any data. 
        -- We do this by adding a condition that is always false.
        SET @tmp_cve_overview_sql = CONCAT(@tmp_cve_overview_sql, ' AND 0 = 1 ');
    END IF;

    SET @tmp_cve_overview_sql = CONCAT(@tmp_cve_overview_sql, ' GROUP BY cve_id');

    PREPARE stmt FROM @tmp_cve_overview_sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;

    SELECT
        CASE
            WHEN cve.severity IS NULL THEN 'Unknown'
            ELSE cve.severity
        END AS severity,
        COUNT(
            CASE
                WHEN cve.severity IS NULL THEN 'Unknown'
                ELSE cve.severity
            END
        ) AS severity_count
    FROM
        tmp_cve_overview
    LEFT JOIN cve ON cve.cve_id = tmp_cve_overview.cve_id
    GROUP BY
        cve.severity;

END;