#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
# licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN 'AS IS' BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/
from typing import Dict, Tuple
from collections import defaultdict
from elasticsearch import ElasticsearchException
from sqlalchemy import case, func
from sqlalchemy.exc import SQLAlchemyError
from vulcanus.common import hash_value
from vulcanus.database.helper import sort_and_page
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import (
    DATABASE_INSERT_ERROR,
    NO_DATA,
    DATABASE_QUERY_ERROR,
    DATABASE_UPDATE_ERROR,
    SUCCEED,
    PARTIAL_SUCCEED,
)

from apollo.conf.constant import TaskStatus
from apollo.database.table import (
    CveAffectedPkgs,
    Task,
    HotpatchRemoveTask,
    Host,
)
from apollo.function.customize_exception import EsOperationError
from apollo.database.proxy.task.base import TaskProxy


class HotpatchRemoveProxy(TaskProxy):
    def update_hotpatch_remove_cve_status(self, task_id, cve_id, host_id, status):
        """
        Every time a cve in a host has been tried to be fixed or rollbacked, update the status

        Args:
            task_id (str): task id
            cve_id (str): cve id
            host_id (str): host id
            status (str): status

        Returns:
            int: status code
        """
        try:
            status_code = self._update_hotpatch_remove_cve_status(task_id, cve_id, host_id, status)
            if status_code != SUCCEED:
                return status_code
            self.session.commit()
            LOGGER.debug("Finished updating cve host status.")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Updating cve host status failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def _update_hotpatch_remove_cve_status(self, task_id, cve_id, host_id, status):
        """
        update a cve's one host's result of a cve task or rollback
        """
        status_query = self.session.query(HotpatchRemoveTask).filter(
            HotpatchRemoveTask.task_id == task_id,
            HotpatchRemoveTask.cve_id == cve_id,
            HotpatchRemoveTask.host_id == host_id,
        )

        if not status_query.count():
            LOGGER.error("Updating cve host status failed due to no data found.")
            return NO_DATA
        if status_query.count() > 1:
            LOGGER.error("Updating cve host status failed due to internal error.")
            return DATABASE_UPDATE_ERROR

        status_query.one().status = status
        return SUCCEED

    def init_hotpatch_remove_task(self, task_id, cve_list, status=TaskStatus.RUNNING):
        """
        Before hotpatch remove, set related host status to 'running'

        Args:
            task_id (str): task id
            cve_list (list): cve id list, it can be empty which means all cve id.
            status (str): cve status
        Returns:
            int: status code
        """
        try:
            filters = {HotpatchRemoveTask.task_id == task_id}
            if cve_list:
                filters.add(HotpatchRemoveTask.cve_id.in_(cve_list))
            status_query = self.session.query(HotpatchRemoveTask).filter(*filters)
            status_query.update({HotpatchRemoveTask.status: status}, synchronize_session=False)
            self.session.commit()
            LOGGER.debug("Finished init cve task's status and progress.")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Init cve task's status and progress failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def get_hotpatch_remove_basic_info(self, task_id):
        """
        Get hotpatch remove task basic info of the task id, for generating the task info.

        Args:
            task_id (str): task_id

        Returns:
            int: status code
            dict: e.g.
                {
                    "task_id": "1",
                    "task_name": "热补丁移除",
                    "task_type": "hotpatch remove",
                    "total_hosts": ["id1", "id2"],
                    "tasks": [
                        {
                            "host_id": "id1",
                            "cves": [
                                {
                                    "cve_id": "cve1"
                                }
                            }
                        }
                    ]
                }
        """
        result = dict()
        try:
            status_code, result = self._get_hotpatch_remove_basic_info(task_id)
            LOGGER.debug("Finished getting the basic info of hotpatch remove task.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting the basic info of hotpatch remove task failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_hotpatch_remove_basic_info(self, task_id: str) -> Tuple[int, Dict]:
        """
        query hotpatch remove task's basic info
        Args:
            task_id (str): task id

        Returns:
            int
            dict
        """
        task_hosts = (
            self.session.query(HotpatchRemoveTask.cve_id, HotpatchRemoveTask.host_id)
            .filter(HotpatchRemoveTask.task_id == task_id)
            .all()
        )

        task_basic_info = self._query_task_basic_info(task_id).first()
        if not all([task_hosts, task_basic_info]):
            LOGGER.debug("No data found when getting the info of cve task: %s." % task_id)
            return NO_DATA, {}

        task_info = {
            "task_id": task_basic_info.task_id,
            "task_name": task_basic_info.task_name,
            "task_type": task_basic_info.task_type,
            "total_hosts": [],
            "tasks": [],
        }
        tasks = dict()
        for task_host in task_hosts:
            if task_host.host_id in tasks:
                tasks[task_host.host_id].append(task_host.cve_id)
            else:
                tasks[task_host.host_id] = [task_host.cve_id]
        task_info["total_hosts"] = list(tasks.keys())
        task_info["tasks"] = [{"host_id": host_id, "cves": cves} for host_id, cves in tasks.items()]

        return SUCCEED, task_info

    def generate_hotpatch_remove_task(self, data):
        """
        For generating, save hotpatch remove task basic info to mysql, init task info in es.

        Args:
            data (dict): e.g.
                {
                    "username": "admin",
                    "task_id": "",
                    "task_name": "",
                    "task_type": "",
                    "description": "",
                    "create_time": 1,
                    "info": [
                        {
                            "host_id": "id1",
                            "cves": [
                                {
                                    "cve_id": "cve1"
                                }
                            ],
                        }
                    ]
                }

        Returns:
            int: status code
        """
        try:
            self._gen_hotpatch_remove_task(data)
            self.session.commit()
            LOGGER.debug("Finished generating hotpatch remove task.")
            return SUCCEED
        except (SQLAlchemyError, ElasticsearchException, EsOperationError) as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Generating hotpatch remove task failed due to internal error.")
            return DATABASE_INSERT_ERROR

    def _gen_hotpatch_remove_task(self, data):
        task_id = data["task_id"]
        task_cve_host = dict()
        cves = dict()
        for task_info in data.pop("info"):
            task_cve_host[task_info["host_id"]] = []
            for cve in task_info["cves"]:
                cves[cve["cve_id"]] = cves[cve["cve_id"]] + 1 if cve["cve_id"] in cves else 1
                task_cve_host[task_info["host_id"]].append(cve["cve_id"])

        task_cve_host_rows = []
        hosts = self.session.query(Host).filter(Host.host_id.in_(list(task_cve_host.keys()))).all()
        for host in hosts:
            host_info = {"host_id": host.host_id, "host_name": host.host_name, "host_ip": host.host_ip}
            for cve_id in task_cve_host[host.host_id]:
                task_cve_host_id = hash_value(text=task_id + cve_id + str(host.host_id))
                task_cve_host_rows.append(
                    self._hotpatch_remove_task_cve_row_dict(task_cve_host_id, task_id, cve_id, host_info)
                )

        # insert data into mysql tables
        data["host_num"] = len(task_cve_host.keys())
        self.session.add(Task(**data))
        self.session.bulk_insert_mappings(HotpatchRemoveTask, task_cve_host_rows)

    @staticmethod
    def _hotpatch_remove_task_cve_row_dict(task_cve_host_id, task_id, cve_id, host_info):
        """
        Combined data rows removed by hot patch
        """
        return {
            "task_cve_host_id": task_cve_host_id,
            "task_id": task_id,
            "cve_id": cve_id,
            "host_id": host_info["host_id"],
            "host_name": host_info["host_name"],
            "host_ip": host_info["host_ip"],
            "status": TaskStatus.UNKNOWN,
        }

    def get_hotpatch_remove_task_cve_info(self, data):
        """
        Get the specific info about the hotpatch remove task.

        Args:
            data (dict): parameter, e.g.
                {
                    "task_id": "id1",
                    "sort": "host_num",
                    "direction": "asc",
                    "page": 1,
                    "per_page": 10,
                    "username": "admin",
                    "filter": {
                        "cve_id": "",
                        "status": []
                    }
                }

        Returns:
            int: status code
            dict: task's cve info. e.g.
                {
                    "total_count": 1,
                    "total_page": 1,
                    "result": [{
                        "cve_id": "id1",
                        "package": "tensorflow",
                        "host_num": 3,
                        "status": "running"
                    }]
                }
        """
        result = {}
        try:
            result = self._get_processed_hotpatch_remove_task_cve(data)
            LOGGER.debug("Finished getting task's cve info.")
            return SUCCEED, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting task's cve info failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_hotpatch_remove_task_cve(self, data):
        """
        Query and process hotpatch remove task's cve info
        Args:
            data (dict): query condition

        Returns:
            int: status code
            dict
        """
        result = {"total_count": 0, "total_page": 0, "result": []}

        task_id = data["task_id"]
        task_info = self.session.query(Task).filter(Task.task_id == task_id, Task.username == data["username"]).first()
        if not task_info:
            return result
        filters = self._get_hotpatch_remove_task_filters(data.get("filter", dict()), task_id)
        hotpatch_revmoe_cve_query = self._query_hotpatch_remove_task_cve_info(filters)
        total_count = hotpatch_revmoe_cve_query.count()
        # NO_DATA code is NOT returned because no data situation here is normal
        # with filter
        if not total_count:
            return result
        sort_column = data.get('sort', "cve_id")
        direction, page, per_page = data.get('direction'), data.get('page'), data.get('per_page')
        hotpatch_revmoe_cve_result, total_page = sort_and_page(
            hotpatch_revmoe_cve_query, sort_column, direction, per_page, page
        )
        result['result'] = self._hotpatch_remove_cve_info_row_dict(hotpatch_revmoe_cve_result)
        result['total_page'] = total_page
        result['total_count'] = total_count

        return result

    @staticmethod
    def _get_hotpatch_remove_task_filters(filter_dict, task_id):
        """
        Generate filters to filter cve task's cve info
        (filter by status will be manually implemented)
        Args:
            filter_dict(dict): filter dict to filter cve task's cve info, e.g.
                {
                    "cve_id": ""
                }

        Returns:
            set
        """
        filters = {HotpatchRemoveTask.task_id == task_id}

        if filter_dict.get("cve_id"):
            filters.add(HotpatchRemoveTask.cve_id.like("%" + filter_dict["cve_id"] + "%"))
        if filter_dict.get("status"):
            filters.add(HotpatchRemoveTask.status.in_(filter_dict["status"]))

        return filters

    def _query_hotpatch_remove_task_cve_info(self, filters):
        """
        query needed hotpatch remove task's cve info
        Args:
            filters (set): filter given by user

        Returns:
            sqlalchemy.orm.query.Query. row structure:
                {
                    "cve_id": "CVE-2021-0001",
                    "package": "tensorflow",
                    "host_id": "id1",
                    "status": "fixed"
                }
        """
        cve_packages_subquery = (
            self.session.query(
                CveAffectedPkgs.cve_id,
                func.group_concat(func.distinct(CveAffectedPkgs.package)).label("package"),
            )
            .group_by(CveAffectedPkgs.cve_id)
            .subquery()
        )
        task_cve_query = (
            self.session.query(
                HotpatchRemoveTask.cve_id,
                cve_packages_subquery.c.package,
                func.count(HotpatchRemoveTask.host_id).label("host_num"),
                func.group_concat(func.distinct(HotpatchRemoveTask.status)).label("status"),
            )
            .outerjoin(cve_packages_subquery, cve_packages_subquery.c.cve_id == HotpatchRemoveTask.cve_id)
            .filter(*filters)
            .group_by(HotpatchRemoveTask.cve_id)
        )

        return task_cve_query

    @staticmethod
    def _hotpatch_remove_cve_info_row_dict(hotpatch_revmoe_cve_result):
        """
        Cve information about a hot patch removal task
        """
        hotpatch_revmoe_cves = []
        for cve_row in hotpatch_revmoe_cve_result:
            status = cve_row.status
            if TaskStatus.RUNNING in status:
                status = TaskStatus.RUNNING
            elif TaskStatus.FAIL in status:
                status = TaskStatus.FAIL
            elif TaskStatus.UNKNOWN in status:
                status = TaskStatus.UNKNOWN
            else:
                status = TaskStatus.SUCCEED
            hotpatch_revmoe_cves.append(
                {
                    "cve_id": cve_row.cve_id,
                    "package": cve_row.package,
                    "host_num": cve_row.host_num,
                    "status": status,
                }
            )
        return hotpatch_revmoe_cves

    def get_hotpatch_remove_task_result(self, data):
        """
        Get the result of each cve in the task, in addition to basic info of the task.

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
                    "task_id": "90d0a61e32a811ee8677000c29766160",
                    "host_id": 2,
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "fail"
                    "latest_execute_time": "1691465474",
                    "task_type": "hotpatch remove",
                    "task_result": {
                        "check_items":[
                            {
                                "item":"network",
                                "result":true,
                                "log":"xxxx"
                            }
                        ],
                        "cves": [
                            {
                                "cve_id": "string",
                                "result": "string",
                                "log": "string"
                            }
                        ]
                }
            }]
        """
        result = {}
        try:
            status_code, result = self.get_task_log_info(task_id=data["task_id"], username=data["username"])
            LOGGER.debug("Finished getting hotpatch remove task result.")
            return status_code, result
        except (ElasticsearchException, KeyError) as error:
            LOGGER.error(error)
            LOGGER.error("Getting hotpatch remove task result failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def get_hotpatch_remove_task_host_cve_status(self, data):
        """
        Get the status of each host of the cve in the hotpatch remove task

        Args:
            data (dict): parameter, e.g.
                {
                    "task_id": "id1",
                    "cve_list": ["cve1"],  // if empty, query all cve
                    "username": "admin"
                }

        Returns:
            int: status code
            dict: query result. e.g.
                {
                    "result": {
                        "cve1": [
                            {
                                "host_id": "id1",
                                "host_name": "name1",
                                "host_ip": "127.0.0.1",
                                "status": "running"
                            }
                        ]
                    }
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_hotpatch_remove_task_host_cve_status(data)
            LOGGER.debug("Finished getting the status of each host of the cve in hotpatch remove task")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error(
                "Getting the status of each host of the cve in hotpatch remove task failed due to internal error."
            )
            return DATABASE_QUERY_ERROR, result

    def _get_processed_hotpatch_remove_task_host_cve_status(self, data):
        """
        query and process the hosts' status of cve in a cve task
        Args:
            data (dict): parameter

        Returns:
            dict
        """
        task_id = data["task_id"]
        cve_list = data["cve_list"]
        username = data["username"]
        status_query = self._query_hotpatch_remove_task_cve_status(username, task_id, cve_list, with_host=True)

        if not status_query.all():
            LOGGER.debug(
                "No data found when getting the hosts' status of cve '%s' " "in cve task: %s." % (cve_list, task_id)
            )
            return NO_DATA, {"result", {}}

        result = defaultdict(list)
        for row in status_query:
            result[row.cve_id].append(
                {"host_id": row.host_id, "host_name": row.host_name, "host_ip": row.host_ip, "status": row.status}
            )

        succeed_list = list(result.keys())
        fail_list = list(set(cve_list) - set(succeed_list))

        if fail_list:
            LOGGER.debug(
                "No data found when getting the hosts' status of cve '%s' " "in cve task: %s." % (fail_list, task_id)
            )
            return PARTIAL_SUCCEED, {"result": dict(result)}

        return SUCCEED, {"result": dict(result)}

    def _query_hotpatch_remove_task_cve_status(self, username, task_id, cve_list, with_host=False):
        """
        query the hosts' status of given cve list in a cve task
        Args:
            username (str): user name of the request
            task_id (str): task id
            cve_list (list): cve id list, if empty, query all cve
            with_host (bool): with host info or not

        Returns:
            sqlalchemy.orm.query.Query
        """
        filters = {Task.username == username, HotpatchRemoveTask.task_id == task_id}
        if cve_list:
            filters.add(HotpatchRemoveTask.cve_id.in_(cve_list))

        if with_host:
            status_query = (
                self.session.query(
                    HotpatchRemoveTask.status,
                    HotpatchRemoveTask.cve_id,
                    HotpatchRemoveTask.host_id,
                    HotpatchRemoveTask.host_name,
                    HotpatchRemoveTask.host_ip,
                )
                .join(Task, Task.task_id == HotpatchRemoveTask.task_id)
                .filter(*filters)
            )
        else:
            status_query = (
                self.session.query(HotpatchRemoveTask.status, HotpatchRemoveTask.cve_id)
                .join(Task, Task.task_id == HotpatchRemoveTask.task_id)
                .filter(*filters)
            )
        return status_query

    def get_hotpatch_remove_task_cve_progress(self, data):
        """
        Get progress and status of each cve in the hotpatch remove task.

        Args:
            data (dict): parameter, e.g.
                {
                    "task_id": "id1",
                    "cve_list": ["cve1"], if empty, query all cve
                    "username": "admin"
                }

        Returns:
            int: status code
            dict: cve's progress and status info. e.g.
                {
                    "result": {
                        "cve1": {
                            "progress": 1,
                            "status": "running"
                        }
                    }
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_hotpatch_remove_task_cve_progress(data)
            LOGGER.debug("Finished getting the progress and status of the cve in hotpatch remove task")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error(
                "Getting the progress and status of the cve in hotpatch remove task failed due to internal error."
            )
            return DATABASE_QUERY_ERROR, result

    def _get_processed_hotpatch_remove_task_cve_progress(self, data):
        """
        query and process the progress and status of cve in the hotpatch remove task.
        Args:
            data (dict): parameter

        Returns:
            dict
        """
        task_id = data["task_id"]
        cve_list = data["cve_list"]
        username = data["username"]
        progress_query = self._query_hotpatch_remove_task_status_progress(username, task_id, cve_list)

        if not progress_query.all():
            LOGGER.debug(
                "No data found when getting the status and progress of cve '%s' "
                "in cve task: %s." % (cve_list, task_id)
            )
            return NO_DATA, {"result": {}}

        result = {}
        for row in progress_query:
            cve_id = row.cve_id
            if row.running:
                status = TaskStatus.RUNNING
            elif row.unknown:
                status = TaskStatus.UNKNOWN
            elif row.fail:
                status = TaskStatus.FAIL
            else:
                status = TaskStatus.SUCCEED
            result[cve_id] = {"progress": int(row.total - row.running), "status": status}

        succeed_list = list(result.keys())
        fail_list = list(set(cve_list) - set(succeed_list))

        if fail_list:
            LOGGER.debug(
                "No data found when getting the status and progress of cve '%s' "
                "in cve task: %s." % (fail_list, task_id)
            )
            return PARTIAL_SUCCEED, {"result": result}

        return SUCCEED, {"result": result}

    def _query_hotpatch_remove_task_status_progress(self, username, task_id, cve_list):
        """
        query hotpatch remove task's assigned cve's status and progress
        Args:
            username (str): user name
            task_id (str): task id
            cve_list (list): cve id list, if empty, query all cve

        Returns:
            sqlalchemy.orm.query.Query
        """
        filters = {Task.username == username, HotpatchRemoveTask.task_id == task_id}
        if cve_list:
            filters.add(HotpatchRemoveTask.cve_id.in_(cve_list))
        # Count the number of states, sql e.g
        # sum(case when status='running' then 1 else 0 end) as running
        task_query = (
            self.session.query(
                HotpatchRemoveTask.cve_id,
                func.sum(case([(HotpatchRemoveTask.status == TaskStatus.RUNNING, 1)], else_=0)).label("running"),
                func.sum(case([(HotpatchRemoveTask.status == TaskStatus.UNKNOWN, 1)], else_=0)).label("unknown"),
                func.sum(case([(HotpatchRemoveTask.status == TaskStatus.FAIL, 1)], else_=0)).label("fail"),
                func.count().label("total"),
            )
            .join(Task, Task.task_id == HotpatchRemoveTask.task_id)
            .filter(*filters)
            .group_by(HotpatchRemoveTask.cve_id)
        )
        return task_query
