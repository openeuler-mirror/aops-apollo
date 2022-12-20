CREATE TABLE IF NOT EXISTS `cve` (
    `cve_id`        VARCHAR(20)  NOT NULL COMMENT 'cve id', 
    `affected_os`   VARCHAR(200) NULL, 
    `unaffected_os` VARCHAR(200) NULL, 
    `severity`      VARCHAR(20)  NULL     COMMENT '严重程度', 
    `cvss_score`    VARCHAR(20)  NULL     COMMENT 'cve分数', 
    `reboot`        TINYINT(1)   NULL     COMMENT '修复该cve是否需要重启', 
    `publish_time`  VARCHAR(20)  NULL     COMMENT '发布日期', 
    PRIMARY KEY (`cve_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci ROW_FORMAT=DYNAMIC  COMMENT='cve详细信息';

CREATE TABLE IF NOT EXISTS `cve_afftected_pkgs` (
    `cve_id`  VARCHAR(20) NOT NULL, 
    `package` VARCHAR(40) NOT NULL, 
    PRIMARY KEY (`cve_id`,`package`), 
    KEY `cve_id_auto_index` (`cve_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci ROW_FORMAT=DYNAMIC ;

CREATE TABLE IF NOT EXISTS `cve_host_match` (
    `cve_id`   VARCHAR(20) NOT NULL COMMENT 'cve id', 
    `host_id`  VARCHAR(20) NOT NULL COMMENT '主机id', 
    `affected` TINYINT(1)  NOT NULL COMMENT '是否受影响', 
    PRIMARY KEY (`cve_id`,`host_id`), 
    UNIQUE KEY `联合主键` (`cve_id`,`host_id`), 
    KEY `FK_cve_host_cve_id_auto_index` (`cve_id`), 
    KEY `FK_cve_host_host_id_auto_index` (`host_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci ROW_FORMAT=DYNAMIC  COMMENT='host cve 相关信息';

CREATE TABLE IF NOT EXISTS `cve_task` (
    `cve_id`   VARCHAR(20)               NOT NULL COMMENT 'cve id', 
    `task_id`  VARCHAR(20)               NOT NULL COMMENT '任务id', 
    `reboot`   TINYINT(1)                NULL     COMMENT '是否重启', 
    `progress` INT(11) UNSIGNED ZEROFILL NULL     COMMENT '进度', 
    `host_num` INT(11)                   NULL     COMMENT '主机数量', 
    PRIMARY KEY (`cve_id`,`task_id`), 
    KEY `FK_task_cve_task_id_auto_index` (`task_id`), 
    KEY `FK_task_cve_cve_id_auto_index` (`cve_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci ROW_FORMAT=DYNAMIC  COMMENT='任务关联cve信息';

CREATE TABLE IF NOT EXISTS `cve_user_status` (
    `cve_id`   VARCHAR(20) NOT NULL COMMENT 'cve id', 
    `username` VARCHAR(40) NOT NULL COMMENT '所属用户', 
    `status`   VARCHAR(20) NULL, 
    PRIMARY KEY (`cve_id`,`username`), 
    KEY `FK_cve_status_cve_id_auto_index` (`cve_id`), 
    KEY `FK_cve_status_user_auto_index` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci ROW_FORMAT=DYNAMIC  COMMENT='cve状态';

CREATE TABLE IF NOT EXISTS `host` (
    `id`        INT(11)     NOT NULL AUTO_INCREMENT COMMENT 'id', 
    `host_id`   VARCHAR(20) NOT NULL COMMENT '主机id', 
    `repo_name` VARCHAR(20) NOT NULL COMMENT 'repo', 
    `last_scan` INT(11)     NULL, 
    PRIMARY KEY (`id`), 
    KEY `FK_host_repo_name_auto_index` (`repo_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci ROW_FORMAT=DYNAMIC  COMMENT='host cve相关信息';

CREATE TABLE IF NOT EXISTS `repo` (
    `repo_id`   INT(11)      NOT NULL AUTO_INCREMENT COMMENT 'id', 
    `repo_name` VARCHAR(20)  NOT NULL COMMENT 'repo名称', 
    `repo_data` VARCHAR(512) NOT NULL COMMENT 'repo内容', 
    `username`  VARCHAR(40)  NOT NULL COMMENT '所属用户', 
    `repo_attr` VARCHAR(20)  NOT NULL COMMENT '对应操作系统版本', 
    PRIMARY KEY (`repo_id`), 
    KEY `FK_repo_user_auto_index` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci ROW_FORMAT=DYNAMIC ;

CREATE TABLE IF NOT EXISTS `task_cve_host` (
    `task_id`   VARCHAR(32) NOT NULL COMMENT '任务id', 
    `host_id`   VARCHAR(32) NOT NULL COMMENT '主机id', 
    `cve_id`    VARCHAR(20) NOT NULL COMMENT 'cve id', 
    `host_name` VARCHAR(20) NOT NULL COMMENT '主机名', 
    `public_ip` VARCHAR(16) NOT NULL COMMENT '主机IP', 
    `status`    VARCHAR(20) NOT NULL COMMENT '主机cve修复状态', 
    PRIMARY KEY (`task_id`,`host_id`), 
    KEY `FK_task_cve_host_task_id_auto_index` (`task_id`), 
    KEY `FK_task_cve_host_host_id_auto_index` (`host_id`), 
    KEY `FK_task_cve_host_cve_id_auto_index` (`cve_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci ROW_FORMAT=DYNAMIC  COMMENT='任务关联cve-host信息';

CREATE TABLE IF NOT EXISTS `task_host_repo` (
    `task_id`   VARCHAR(32) NOT NULL COMMENT '任务ID', 
    `host_id`   VARCHAR(32) NOT NULL COMMENT '主机ID', 
    `public_ip` VARCHAR(16) NOT NULL COMMENT '主机IP', 
    `host_name` VARCHAR(20) NOT NULL COMMENT '主机名', 
    `repo_name` VARCHAR(20) NOT NULL COMMENT 'repo名称', 
    `status`    VARCHAR(20) NULL     COMMENT '状态', 
    PRIMARY KEY (`task_id`), 
    KEY `FK_task_repo_task_id_auto_index` (`task_id`), 
    KEY `FK_task_repo_host_id_auto_index` (`host_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci ROW_FORMAT=DYNAMIC  COMMENT='任务关联repo信息';

CREATE TABLE IF NOT EXISTS `user` (
    `username` VARCHAR(40) NOT NULL, 
    `password` CHAR(255)   NULL, 
    PRIMARY KEY (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci ROW_FORMAT=DYNAMIC  COMMENT='manager侧';

CREATE TABLE IF NOT EXISTS `vul_task` (
    `task_id`             VARCHAR(32)  NOT NULL COMMENT '任务id', 
    `task_type`           VARCHAR(10)  NOT NULL COMMENT '任务类型', 
    `description`         VARCHAR(512) NOT NULL COMMENT '任务描述', 
    `task_name`           VARCHAR(20)  NOT NULL COMMENT '任务名称', 
    `latest_execute_time` INT(11)      NULL     COMMENT '最新执行时间', 
    `need_reboot`         INT(11)      NULL     COMMENT '需要重启的主机数量', 
    `auto_reboot`         TINYINT(1)   NULL     COMMENT '是否自动重启', 
    `host_num`            INT(11)      NULL     COMMENT '主机数量', 
    `check_items`         VARCHAR(32)  NULL     COMMENT '检查项', 
    `username`            VARCHAR(40)  NULL     COMMENT '用户', 
    PRIMARY KEY (`task_id`), 
    KEY `FK_cve_task_user_auto_index` (`need_reboot`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci ROW_FORMAT=DYNAMIC  COMMENT='任务相关信息';

ALTER TABLE cve_afftected_pkgs
ADD CONSTRAINT `cve_id` FOREIGN KEY (`cve_id`) REFERENCES `cve` (`cve_id`) ON DELETE RESTRICT ON UPDATE RESTRICT ;

ALTER TABLE cve_host_match
ADD CONSTRAINT `FK_cve_host_cve_id` FOREIGN KEY (`cve_id`) REFERENCES `cve` (`cve_id`) ON DELETE RESTRICT ON UPDATE RESTRICT , 
ADD CONSTRAINT `FK_cve_host_host_id` FOREIGN KEY (`host_id`) REFERENCES `host` (`host_id`) ON DELETE RESTRICT ON UPDATE RESTRICT ;

ALTER TABLE cve_task
ADD CONSTRAINT `FK_task_cve_cve_id` FOREIGN KEY (`cve_id`) REFERENCES `cve` (`cve_id`) ON DELETE RESTRICT ON UPDATE RESTRICT , 
ADD CONSTRAINT `FK_task_cve_task_id` FOREIGN KEY (`task_id`) REFERENCES `vul_task` (`task_id`) ON DELETE RESTRICT ON UPDATE RESTRICT ;

ALTER TABLE cve_user_status
ADD CONSTRAINT `FK_cve_status_cve_id` FOREIGN KEY (`cve_id`) REFERENCES `cve` (`cve_id`) ON DELETE RESTRICT ON UPDATE RESTRICT , 
ADD CONSTRAINT `user_name` FOREIGN KEY (`username`) REFERENCES `user` (`username`) ON DELETE RESTRICT ON UPDATE RESTRICT ;

ALTER TABLE host
ADD CONSTRAINT `FK_host_repo_name` FOREIGN KEY (`repo_name`) REFERENCES `repo` (`repo_name`) ON DELETE RESTRICT ON UPDATE RESTRICT ;

ALTER TABLE repo
ADD CONSTRAINT `username` FOREIGN KEY (`username`) REFERENCES `user` (`username`) ON DELETE RESTRICT ON UPDATE RESTRICT ;

ALTER TABLE task_cve_host
ADD CONSTRAINT `fk_task_id` FOREIGN KEY (`task_id`) REFERENCES `vul_task` (`task_id`) ON DELETE RESTRICT ON UPDATE RESTRICT , 
ADD CONSTRAINT `fk_cve_id` FOREIGN KEY (`cve_id`) REFERENCES `cve` (`cve_id`) ON DELETE RESTRICT ON UPDATE RESTRICT ;

ALTER TABLE task_host_repo
ADD CONSTRAINT `task_id` FOREIGN KEY (`task_id`) REFERENCES `vul_task` (`task_id`) ON DELETE RESTRICT ON UPDATE RESTRICT ;