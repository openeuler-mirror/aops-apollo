#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
# licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN 'AS IS' BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/
from typing import Tuple, Optional

import sqlalchemy.orm
from elasticsearch import ElasticsearchException
from flask import request
from sqlalchemy import or_, func, case
from sqlalchemy.exc import SQLAlchemyError

from apollo.conf.constant import TaskType, TaskStatus
from apollo.database.proxy.task.base import TaskProxy
from apollo.database.table import Task, CveRollbackTask, CveFixTask
from vulcanus.database.helper import sort_and_page
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import (
    DATABASE_INSERT_ERROR,
    NO_DATA,
    SUCCEED,
    PARAM_ERROR,
    DATABASE_UPDATE_ERROR,
    DATABASE_QUERY_ERROR,
)


class CveRollbackTaskProxy(TaskProxy):

    def generate_cve_rollback_task(self, data: dict) -> Tuple[int, Optional[str]]:
        """
        For generating, save cve rollback task basic info to mysql, init task info in es.

        Args:
            data (dict): e.g.
                {
                    "username": "admin",
                    "task_id": "",
                    "fix_task_id": "",
                    "task_type": "",
                    "create_time": 1
                }

        Returns:
            int: status code
        """
        try:
            status_code, msg = self._generate_cve_rollback_task(data)
            if status_code != SUCCEED:
                return status_code, msg
            self.session.commit()
            LOGGER.debug("Finished generating cve task.")
            return status_code, msg
        except (SQLAlchemyError, KeyError) as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Generating cve task failed due to internal error.")
            return DATABASE_INSERT_ERROR, None

    def _generate_cve_rollback_task(self, data) -> Tuple[int, Optional[str]]:
        """
        generate cve rollback task:
        1. check the task to be rolled back valid or not
        2. insert task basic info into mysql Task table
        3. insert rollback task info into mysql CveRollbackTask table
        Args:
            data (dict): cve rollback task info
        """
        fix_task_id = data["fix_task_id"]
        fix_task_basic_info = self._query_task_basic_info(fix_task_id).one()
        if fix_task_basic_info.task_type != TaskType.CVE_FIX:
            msg = "Task '%s' is '%s' task, cannot be rolled back." % (fix_task_id, fix_task_basic_info.task_type)
            LOGGER.error(msg)
            return PARAM_ERROR, msg

        fix_task_info = self.session.query(CveFixTask).filter(CveFixTask.task_id == fix_task_id).all()
        if not fix_task_info:
            msg = "No data found when getting the info of cve task for rollback: %s." % fix_task_id
            LOGGER.error(msg)
            return NO_DATA, msg

        # host_list = [row.host_id for row in fix_task_info]
        # exist_host_query = self.session.query(Host.host_id).filter(Host.host_id.in_(host_list))
        # exist_host_list = [row.host_id for row in exist_host_query]
        # fail_list = list(set(host_list) - set(exist_host_list))
        # # no need to generate task when any host doesn't exist
        # if fail_list:
        #     msg = "Some hosts of cve task '%s' for rollback don't exist." % fix_task_id
        #     LOGGER.debug(msg)
        #     LOGGER.debug(','.join(fail_list))
        #     return PARAM_ERROR, msg

        task_table_row = self._gen_task_row(data, fix_task_basic_info)
        rollback_task_table_rows = self._gen_cve_rollback_task_rows(data["task_id"], fix_task_id, fix_task_info)
        self.session.add(Task(**task_table_row))
        self.session.bulk_insert_mappings(CveRollbackTask, rollback_task_table_rows)
        return SUCCEED, None

    @staticmethod
    def _gen_task_row(data: dict, cve_fix_task_info: sqlalchemy.orm.Query) -> dict:
        lang_info = request.headers.get("Accept-Language")
        if lang_info:
            lang = lang_info.split(',')[0].split(';')[0]
        else:
            lang = "en"

        fix_task_description = cve_fix_task_info.description
        fix_task_name = cve_fix_task_info.task_name
        host_num = cve_fix_task_info.host_num

        if lang.startswith("en"):
            task_name = "Rollback task: %s" % fix_task_name
            description = "Origin task description: %s" % fix_task_description
        else:
            task_name = "回滚: %s" % fix_task_name
            description = "原CVE修复任务描述: %s" % fix_task_description

        task_data = {
            "cluster_id": data["cluster_id"],
            "task_id": data["task_id"],
            "task_type": data["task_type"],
            "create_time": data["create_time"],
            "task_name": task_name,
            "description": description,
            "host_num": host_num,
            "username": data.get("username"),
        }
        return task_data

    @staticmethod
    def _gen_cve_rollback_task_rows(task_id: str, fix_task_id: str, cve_fix_task_info: sqlalchemy.orm.Query) -> list:
        rollback_task_rows = []
        for row in cve_fix_task_info:
            rollback_task_row = {
                "task_id": task_id,
                "fix_task_id": fix_task_id,
                "rollback_type": row.fix_way,
                "host_id": row.host_id,
                "host_ip": row.host_ip,
                "host_name": row.host_name,
                "cves": row.cves,
                "installed_rpm": row.available_rpm,
                "target_rpm": row.installed_rpm,
                "status": TaskStatus.UNKNOWN,
                "dnf_event_start": row.dnf_event_start,
                "dnf_event_end": row.dnf_event_end,
            }
            rollback_task_rows.append(rollback_task_row)
        return rollback_task_rows

    def get_cve_rollback_task_host_info(self, data) -> Tuple[str, dict]:
        """
        Get the specific info about the cve rollback task.

        Args:
            data (dict): parameter, e.g.
                {
                    "task_id": "id1",
                    "page": 1,
                    "per_page": 10,
                    "username": "admin",
                    "filter": {
                        "search_key": host_name or host_ip,
                        "status": []
                    }
                }

        Returns:
            str: status code
            dict: task's cve info. e.g.
                {
                    "total_count": 1,
                    "total_page": 1,
                    "result": [{
                        "host_id": 1,
                        "host_name": "xxx",
                        "host_ip": "127.0.0.1",
                        "cve_num": 3,
                        "status": "running/succeed/fail/unknown"
                    }]
                }
        """
        result = {}
        try:
            result = self._get_processed_cve_rollback_task_host(data)
            LOGGER.debug("Finished getting cve rollback task's host info.")
            return SUCCEED, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve rollback task's host info failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_cve_rollback_task_host(self, data):
        """
        Query and process cve rollback task's host info
        Args:
            data (dict): query condition

        Returns:
            dict
        """
        result = {"total_count": 0, "total_page": 0, "result": []}

        task_id = data["task_id"]
        filter_dict = data.get("filter", {})
        needed_status, host_filters = self._get_cve_rollback_task_filters(filter_dict)
        cve_rollback_task_host_query = self._query_cve_rollback_task_host(task_id, needed_status, host_filters)

        total_count = cve_rollback_task_host_query.count()
        if not total_count:
            return result

        page, per_page = data.get('page'), data.get('per_page')
        processed_result, total_page = sort_and_page(
            query_result=cve_rollback_task_host_query, column=None, direction=None, per_page=per_page, page=page
        )
        host_info_list = self._process_cve_rollback_task_host(cve_rollback_task_host_query)

        result['result'] = host_info_list
        result['total_page'] = total_page
        result['total_count'] = total_count
        return result

    @staticmethod
    def _get_cve_rollback_task_filters(filter_dict) -> Tuple[list, set]:
        """
        Generate filters to filter cve rollback task's host info
        (filter by status will be implemented later in the query sentence)
        Args:
            filter_dict(dict): filter dict to filter cve task's host info, e.g.
                {
                    "search_key": "1/127.0.0.1",
                    "status": ["succeed", "unknown", "fail", "running"]
                }

        Returns:
            list: needed status list
            set: filter set when filtered by search key
        """
        filters = set()
        # only filter host name, will filter status outside
        if filter_dict.get("search_key"):
            filters.add(
                or_(
                    CveRollbackTask.host_name.like("%" + filter_dict["search_key"] + "%"),
                    CveRollbackTask.host_ip.like("%" + filter_dict["search_key"] + "%"),
                )
            )

        needed_status = filter_dict.get("status", [])
        return needed_status, filters

    def _query_cve_rollback_task_host(self, task_id, needed_status, host_filters):
        """
        query needed cve rollback task's host info
        Args:
            username (str): username of the request
            task_id (str): task id
            needed_status (list): needed status list
            host_filters (set): filter set when filtered by search key()

        Returns:
            sqlalchemy.orm.query.Query. row structure:
                {
                    "host_id": 1,
                    "host_name": "xxx",
                    "host_ip": "127.0.0.1",
                    "cves": "aaa,bbb,aaa,ccc",
                    "status": "running,succeed,fail,unknown"
                }
        """
        cve_rollback_task_subquery = (
            self.session.query(
                CveRollbackTask.host_id,
                CveRollbackTask.host_name,
                CveRollbackTask.host_ip,
                # this sentence will get distinct value joined by ','
                func.group_concat(func.distinct(CveRollbackTask.status)).label("status"),
                func.group_concat(func.distinct(CveRollbackTask.cves)).label("cves"),
            )
            .outerjoin(Task, Task.task_id == CveRollbackTask.task_id)
            .filter(CveRollbackTask.task_id == task_id)
            .filter(*host_filters)
            .group_by(CveRollbackTask.host_id, CveRollbackTask.host_ip, CveRollbackTask.host_name)
            .subquery()
        )
        cve_rollback_task_status_subquery = self.session.query(
            cve_rollback_task_subquery.c.host_id,
            cve_rollback_task_subquery.c.host_name,
            cve_rollback_task_subquery.c.host_ip,
            case(
                [
                    (cve_rollback_task_subquery.c.status.contains(TaskStatus.RUNNING), TaskStatus.RUNNING),
                    (cve_rollback_task_subquery.c.status.contains(TaskStatus.FAIL), TaskStatus.FAIL),
                    (cve_rollback_task_subquery.c.status.contains(TaskStatus.UNKNOWN), TaskStatus.UNKNOWN),
                ],
                else_=TaskStatus.SUCCEED,
            ).label("status"),
            cve_rollback_task_subquery.c.cves,
        ).subquery()

        status_filters = set()
        if needed_status:
            status_filters = {cve_rollback_task_status_subquery.c.status.in_(needed_status)}

        cve_rollback_task_query = self.session.query(
            cve_rollback_task_status_subquery.c.host_id,
            cve_rollback_task_status_subquery.c.host_ip,
            cve_rollback_task_status_subquery.c.host_name,
            cve_rollback_task_status_subquery.c.status,
            cve_rollback_task_status_subquery.c.cves,
        ).filter(*status_filters)
        return cve_rollback_task_query

    @staticmethod
    def _process_cve_rollback_task_host(task_host_query) -> list:
        """
        process cve rollback task query data, get each host's total status and cve_num, then filter by status
        Args:
            task_host_query (sqlalchemy.orm.query.Query): query result of cve rollback task's host info
                each row's structure:
                    {
                        "host_id": 1,
                        "host_name": "xxx",
                        "host_ip": "127.0.0.1",
                        "cves": "aaa,bbb,aaa,ccc",
                        "status": "running/succeed/fail/unknown"
                    }
        Returns:
            list. e.g.
                [{
                    "host_id": 1,
                    "host_name": "xxx",
                    "host_ip": "127.0.0.1",
                    "cve_num": 3,
                    "status": "running/succeed/fail/unknown"
                }]
        """
        result = []
        for row in task_host_query:
            cve_num = len(set(row.cves.split(",")))
            host_info = {
                "host_id": row.host_id,
                "host_name": row.host_name,
                "host_ip": row.host_ip,
                "cve_num": cve_num,
                "status": row.status,
            }
            result.append(host_info)
        return result

    def get_cve_rollback_task_info_for_execution(self, task_id: str) -> Tuple[str, dict]:
        """
        Get cve rollback task info of the task id, used as body sent to zeus.
        right now, assume each host only has one action in a rollback task
        Args:
            task_id (str): task_id

        Returns:
            int: status code
            dict: e.g.
                {
                    "task_id": "",
                    "task_name": "回滚任务",
                    "fix_task_id": "string",
                    "task_type": "cve rollback",
                    "rollback_type": "hotpatch/coldpatch",
                    "check_items": ["network"],
                    "tasks": [
                        {
                            "host_id": 1,
                            "installed_rpm": "kernel-5.1.10",
                            "target_rpm": "kernel-5.1.9",
                            "dnf_event_start": 1, or None by default
                            "dnf_event_end": 2, or None by default
                        }
                     ]
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_cve_rollback_task(task_id)
            LOGGER.debug("Finished getting the info of cve rollback task.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting the info of cve rollback task failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_cve_rollback_task(self, task_id: str) -> Tuple[str, dict]:
        """
        query and process cve rollback task's info
        Args:
            task_id (str): task id

        Returns:
            str
            dict
        """
        rollback_task_info = self._query_cve_rollback_task_info(task_id).all()
        basic_task = self._query_task_basic_info(task_id).first()
        if not all([rollback_task_info, basic_task]):
            LOGGER.debug("No data found when getting the info of cve rollback task: %s." % task_id)
            return NO_DATA, {}

        fix_task_id = {row.fix_task_id for row in rollback_task_info}
        if len(fix_task_id) != 1:
            LOGGER.debug("Multiple data found when getting the fix_task_id of cve rollback task: %s." % task_id)
            return DATABASE_QUERY_ERROR, {}

        rollback_type = {row.rollback_type for row in rollback_task_info}
        if len(rollback_type) != 1:
            LOGGER.debug("Multiple data found when getting the rollback_type of cve rollback task: %s." % task_id)
            return DATABASE_QUERY_ERROR, {}

        rollback_detail, total_hosts = [], []
        # right now, assume each host only has one action in a rollback task
        for row in rollback_task_info:
            rollback_detail.append(
                {
                    "host_id": row.host_id,
                    "installed_rpm": row.installed_rpm,
                    "target_rpm": row.target_rpm,
                    "dnf_event_start": row.dnf_event_start,
                    "dnf_event_end": row.dnf_event_end,
                }
            )
            if row.host_id not in total_hosts:
                total_hosts.append(row.host_id)

        task_info = {
            "task_id": basic_task.task_id,
            "task_name": basic_task.task_name,
            "task_type": basic_task.task_type,
            "check_items": basic_task.check_items.split(',') if basic_task.check_items else [],
            "fix_task_id": fix_task_id.pop(),
            "rollback_type": rollback_type.pop(),
            "tasks": rollback_detail,
            "total_hosts": total_hosts,
        }
        return SUCCEED, task_info

    def _query_cve_rollback_task_info(self, task_id: str, host_id=None) -> sqlalchemy.orm.Query:
        """
        query host and rpm info of the cve rollback task
        right now, assume each host only has one action in a rollback task
        Args:
            task_id (str): task id

        Returns:
            sqlalchemy.orm.Query
        """
        filters = set()
        if host_id:
            filters = {CveRollbackTask.host_id == host_id}
        task_query = self.session.query(CveRollbackTask).filter(CveRollbackTask.task_id == task_id).filter(*filters)
        return task_query

    def update_cve_rollback_task_status(self, task_id, status, host_id=None) -> str:
        """
        Before roll backing cve fix task, set related hosts' status to 'running',
        After callback from zeus, set the host's status to 'succeed/fail'. Due to rollback task is 'one step' operation
        right now, set the host's all rows' status to the same one.

        Args:
            task_id(str): task id
            status(str): cve status
            host_id(str): host id
        Returns:
            str: status code
        """
        try:
            self._update_cve_rollback_task_status(task_id, status, host_id)
            self.session.commit()
            LOGGER.debug("Finished update cve rollback task's status and progress.")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Update cve rollback task's status failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def _update_cve_rollback_task_status(self, task_id, status, host_id=None):
        filters = {CveRollbackTask.task_id == task_id}
        if host_id:
            filters.add(CveRollbackTask.host_id == host_id)
        self.session.query(CveRollbackTask).filter(*filters).update(
            {CveRollbackTask.status: status}, synchronize_session=False
        )

    def get_cve_rollback_host_rpm_info(self, data: dict) -> Tuple[str, list]:
        """
        get rollback task's host rpm info
        Args:
            data(dict): e.g. {"task_id": "", host_id: ""}

        Returns:
            str: status code
            list: roll backed rpm info of the host.  e.g.
                [{
                    "installed_rpm": "",
                    "target_rpm": "",
                    "cves": "CVE-2023-3332,CVE-2023-23456",
                    "status": "succeed/fail/running/unknown"
                }]
        """
        result = []
        try:
            result = self._get_cve_rollback_host_rpm_info(data)
            LOGGER.debug("Finished getting cve rollback task host's rpm info.")
            return SUCCEED, result
        except (ElasticsearchException, KeyError) as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve rollback task host's rpm info failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_cve_rollback_host_rpm_info(self, data):
        task_id = data["task_id"]
        host_id = data["host_id"]
        host_rpm_info = self._query_cve_rollback_task_info(task_id, host_id)
        result = []
        for row in host_rpm_info:
            rpm_info = {
                "installed_rpm": row.installed_rpm,
                "target_rpm": row.target_rpm,
                "cves": row.cves,
                "status": row.status,
            }
            result.append(rpm_info)
        return result

    def get_cve_rollback_task_result(self, data):
        """
        Get the result of each host in the cve rollback task, in addition to basic info of the task.

        Args:
            data (dict): parameter. e.g.
                {
                    "username": "admin",
                    "task_id": ""
                }

        Returns:
            int: status code
            list: query result. e.g.
                [{
                    "host_id": 2,
                    "host_ip": "127.0.0.1",
                    "host_name": "host1_12001",
                    "latest_execute_time": "1691465474",
                    "task_type": "cve rollback",
                    "task_result": {
                        "check_items":[
                            {
                                "item":"network",
                                "result":true,
                                "log":"xxxx"
                            }
                        ],
                        "rpms": [
                            {
                                "installed_rpm": "",
                                "target_rpm": "",
                                "cves": "CVE-2023-12,CVE-2022-4567"
                            }
                        ],
                        "result": "succeed/fail",
                        "log": "string"
                   }
                }]
        """
        result = {}
        try:
            status_code, result = self._get_cve_rollback_task_result(data)
            LOGGER.debug("Finished getting cve rollback task result.")
            return status_code, result
        except (ElasticsearchException, KeyError) as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve rollback task result failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_cve_rollback_task_result(self, data):
        """
        query cve rollback task result from es.
        """
        task_id = data["task_id"]
        # task log is in the format of returned dict of func
        status_code, task_log = self.get_task_log_info(task_id=task_id)
        if status_code != SUCCEED:
            return status_code, []

        return SUCCEED, task_log
