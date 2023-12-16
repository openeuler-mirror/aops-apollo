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
"""
Time:
Author:
Description: vulnerability related database operation
"""
import json
import threading
from collections import defaultdict
from typing import Tuple

import sqlalchemy.orm
from elasticsearch import ElasticsearchException
from sqlalchemy.exc import SQLAlchemyError
from vulcanus.common import hash_value
from vulcanus.database.helper import sort_and_page, judge_return_code
from vulcanus.database.proxy import MysqlProxy, ElasticsearchProxy
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import (
    DATABASE_DELETE_ERROR,
    DATABASE_INSERT_ERROR,
    NO_DATA,
    DATABASE_QUERY_ERROR,
    DATABASE_UPDATE_ERROR,
    SUCCEED,
    PARTIAL_SUCCEED,
)

from apollo.conf.constant import TASK_INDEX, HostStatus, TaskStatus, TaskType
from apollo.database.table import (
    Task,
    CveFixTask,
    CveRollbackTask,
    HotpatchRemoveTask,
    TaskHostRepoAssociation,
    CveHostAssociation,
    Host,
    User,
)
from apollo.function.customize_exception import EsOperationError


class TaskMysqlProxy(MysqlProxy):
    """
    Task related mysql table operation
    """

    lock = threading.Lock()

    def get_total_host_info(self):
        """
        Get the whole host info of each user.
        Args:

        Returns:
            int: status code
            dict: query result
        """
        temp_res = {}
        result = {"host_infos": temp_res}

        try:
            users = self.session.query(User).all()
            for user in users:
                name = user.username
                temp_res[name] = []
                for host in user.hosts:
                    host_info = {
                        "host_id": host.host_id,
                        "host_name": host.host_name,
                        "host_ip": host.host_ip,
                        "status": host.status,
                    }
                    temp_res[name].append(host_info)
            return SUCCEED, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("query host basic info fail")
            return DATABASE_QUERY_ERROR, result

    def get_task_list(self, data):
        """
        Get the task list.
        Args:
            data (dict): parameter, e.g.
                {
                    "username": "admin",
                    "sort": "host_num",
                    "direction": "asc",
                    "page": 1,
                    "per_page": 10,
                    "filter": {
                        "task_name": "task2",
                        "task_type": ["repo set"]
                    }
                }
        Returns:
            int: status code
            dict: query result. e.g.
                {
                    "total_count": 1,
                    "total_page": 1,
                    "result": [
                        {
                            "task_id": "id1",
                            "task_name": "task1",
                            "task_type": "cve fix",
                            "description": "a long description",
                            "host_num": 12,
                            "create_time": 1111111111
                        }
                    ]
                }
        """
        result = {}
        try:
            result = self._get_processed_task_list(data)
            LOGGER.debug("Finished getting task list.")
            return SUCCEED, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting task list failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_task_list(self, data):
        """
        Get sorted, paged and filtered task list.

        Args:
            data(dict): sort, page and filter info

        Returns:
            dict
        """
        result = {"total_count": 0, "total_page": 0, "result": []}

        filters = self._get_task_list_filters(data.get("filter"))
        task_list_query = self._query_task_list(data["username"], filters)

        total_count = task_list_query.count()
        if not total_count:
            return result

        sort_column = getattr(Task, data.get("sort")) if "sort" in data else None
        direction, page, per_page = (data.get("direction"), data.get("page"), data.get("per_page"))

        processed_query, total_page = sort_and_page(task_list_query, sort_column, direction, per_page, page)

        result["result"] = self._task_list_row2dict(processed_query)
        result["total_page"] = total_page
        result["total_count"] = total_count

        return result

    def _query_task_list(self, username, filters):
        """
        query needed task list
        Args:
            username (str): user name of the request
            filters (set): filter given by user

        Returns:
            sqlalchemy.orm.query.Query
        """
        task_list_query = (
            self.session.query(
                Task.task_id, Task.task_name, Task.task_type, Task.description, Task.host_num, Task.create_time
            )
            .filter(Task.username == username)
            .filter(*filters)
        )
        return task_list_query

    @staticmethod
    def _task_list_row2dict(rows):
        result = []
        for row in rows:
            task_info = {
                "task_id": row.task_id,
                "task_name": row.task_name,
                "task_type": row.task_type,
                "description": row.description,
                "host_num": row.host_num,
                "create_time": row.create_time,
            }
            result.append(task_info)
        return result

    @staticmethod
    def _get_task_list_filters(filter_dict):
        """
        Generate filters

        Args:
            filter_dict(dict): filter dict to filter cve list, e.g.
                {
                    "task_name": "task2",
                    "task_type": ["cve fix", "repo set", "cve scan"]
                }

        Returns:
            set
        """
        filters = set()
        if not filter_dict:
            return filters

        if filter_dict.get("task_name"):
            filters.add(Task.task_name.like("%" + filter_dict["task_name"] + "%"))
        if filter_dict.get("task_type"):
            filters.add(Task.task_type.in_(filter_dict["task_type"]))
        return filters

    def get_task_progress(self, data):
        """
        Get the task progress.
        Args:
            data (dict): parameter, e.g.
                {
                    "task_list": ["task1", "task2"],
                    "username": "admin"
                }
        Returns:
            int: status code
            dict: query result. e.g.
                {
                    "result": {
                        "task1": {
                            "succeed": 1,
                            "fail": 0,
                            "running": 11,
                            "unknown": 0
                        },
                        "task2": {
                            "succeed": 12,
                            "fail": 0,
                            "running": 0,
                            "unknown": 0
                        }
                    }
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_task_progress(data)
            LOGGER.debug("Finished getting task progress.")
            return status_code, result
        except (SQLAlchemyError, KeyError) as error:
            LOGGER.error(error)
            LOGGER.error("Getting task progress failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_task_progress(self, data: dict):
        """
        Get each task's progress
        Args:
            data (dict): task list info

        Returns:
            int: status code
            dict: query result
        """
        task_list = data["task_list"]
        username = data["username"]
        repo_task, cve_task, cve_rollback_task, hp_remove_task = self._split_task_list(username, task_list)

        result = {}
        result.update(self._get_repo_task_progress(repo_task))
        result.update(self._get_cve_series_task_progress(cve_task, TaskType.CVE_FIX))
        result.update(self._get_cve_series_task_progress(cve_rollback_task, TaskType.CVE_ROLLBACK))
        result.update(self._get_cve_series_task_progress(hp_remove_task, TaskType.HOTPATCH_REMOVE))

        succeed_list = list(result.keys())
        fail_list = list(set(task_list) - set(succeed_list))
        if fail_list:
            LOGGER.debug("No data found when getting the progress of task: %s." % fail_list)

        status_dict = {"succeed_list": succeed_list, "fail_list": fail_list}
        status_code = judge_return_code(status_dict, NO_DATA)
        return status_code, {"result": result}

    def _split_task_list(self, username: str, task_list: list) -> Tuple[list, list, list, list]:
        """
        split task list based on task's type
        Args:
            username (str): user name
            task_list (list): task id list

        Returns:
            list: repo task list
            list: cve task list
            liST: cve rollback task list
            list: hotpatch remove task list
        """
        repo_task = []
        cve_task = []
        cve_rollback_task = []
        hp_remove_task = []

        # filter task's type in case of other type added into task table
        task_query = self.session.query(Task.task_id, Task.task_type).filter(
            Task.username == username, Task.task_id.in_(task_list), Task.task_type.in_(TaskType.attribute())
        )

        for row in task_query:
            if row.task_type == TaskType.REPO_SET:
                repo_task.append(row.task_id)
            elif row.task_type == TaskType.CVE_FIX:
                cve_task.append(row.task_id)
            elif row.task_type == TaskType.CVE_ROLLBACK:
                cve_rollback_task.append(row.task_id)
            elif row.task_type == TaskType.HOTPATCH_REMOVE:
                hp_remove_task.append(row.task_id)
        return repo_task, cve_task, cve_rollback_task, hp_remove_task

    @staticmethod
    def _get_status_result():
        def status_dict():
            return {
                TaskStatus.SUCCEED: 0,
                TaskStatus.FAIL: 0,
                TaskStatus.RUNNING: 0,
                TaskStatus.UNKNOWN: 0,
            }

        return defaultdict(status_dict)

    def _get_cve_series_task_progress(self, task_list: list, task_type: str):
        """
        get progress of cve fix task or cve rollback task or hotpatch remove task
        Args:
            task_list (list): cve tasks' id list
            task_type (str): type of cve series tasks.

        Returns:
            dict: e.g.
                {"task1": {"succeed": 1, "fail": 0, "running": 10, "unknown": 1}}

        Raises:
            KeyError
        """

        def defaultdict_set():
            return defaultdict(set)

        task_table_map = {
            TaskType.CVE_FIX: CveFixTask,
            TaskType.CVE_ROLLBACK: CveRollbackTask,
            TaskType.HOTPATCH_REMOVE: HotpatchRemoveTask,
        }
        tasks_dict = defaultdict(defaultdict_set)
        result = self._get_status_result()

        task_query = self._query_cve_series_task_host_status(task_list, task_table_map[task_type])
        for row in task_query:
            tasks_dict[row.task_id][row.host_id].add(row.status)

        for task_id, hosts_dict in tasks_dict.items():
            for status_set in hosts_dict.values():
                host_status = self._get_cve_task_status(status_set)
                result[task_id][host_status] += 1

        succeed_list = list(result.keys())
        fail_list = list(set(task_list) - set(succeed_list))
        if fail_list:
            LOGGER.error("CVE task '%s' exist but status data is not record." % fail_list)
        return result

    def _query_cve_series_task_host_status(self, task_list: list, task_table):
        """
        query host status of cve fix task or cve rollback task or hotpatch remove task
        Args:
            task_list (list): task id list
            task_table (sqlalchemy table): table of cve series tasks. Pay attention, the table must have "task_id",
                "host_id" and "status" columns

        Returns:
            sqlalchemy.orm.query.Query
        """
        task_query = self.session.query(task_table.task_id, task_table.host_id, task_table.status).filter(
            task_table.task_id.in_(task_list)
        )
        return task_query

    @staticmethod
    def _get_cve_task_status(status_set: set):
        """
        get cve task's host or cve's overall status
        Args:
            status_set (set): host or cve's status set

        Returns:
            str
        """
        if TaskStatus.RUNNING in status_set:
            return TaskStatus.RUNNING
        if TaskStatus.UNKNOWN in status_set:
            return TaskStatus.UNKNOWN
        if TaskStatus.FAIL in status_set:
            return TaskStatus.FAIL
        return TaskStatus.SUCCEED

    def _get_repo_task_progress(self, task_list):
        """
        get repo tasks' progress
        Args:
            task_list (list): repo tasks' id list

        Returns:
            dict: e.g.
                {"task1": {"succeed": 1, "fail": 0, "running": 10, "unknown": 1}}

        Raises:
            KeyError
        """
        result = self._get_status_result()

        task_query = self._query_repo_task_host(task_list)
        for row in task_query:
            if row.status == TaskStatus.SUCCEED:
                result[row.task_id][TaskStatus.SUCCEED] += 1
            elif row.status == TaskStatus.FAIL:
                result[row.task_id][TaskStatus.FAIL] += 1
            elif row.status == TaskStatus.RUNNING:
                result[row.task_id][TaskStatus.RUNNING] += 1
            elif row.status == TaskStatus.UNKNOWN:
                result[row.task_id][TaskStatus.UNKNOWN] += 1
            else:
                LOGGER.error("Unknown repo task's host status '%s'" % row.status)

        succeed_list = list(result.keys())
        fail_list = list(set(task_list) - set(succeed_list))
        if fail_list:
            LOGGER.error("Repo task '%s' exist but status data is not record." % fail_list)
        return result

    def _query_repo_task_host(self, task_list):
        """
        query host and CVE's relationship and status of required tasks
        Args:
            task_list (list): task id list

        Returns:
            sqlalchemy.orm.query.Query
        """
        task_query = self.session.query(TaskHostRepoAssociation.task_id, TaskHostRepoAssociation.status).filter(
            TaskHostRepoAssociation.task_id.in_(task_list)
        )
        return task_query

    def get_task_info(self, data):
        """
        Get a task's info
        Args:
            data (dict): parameter, e.g.
                {
                    "task_id": "id1",
                    "username": "admin"
                }
        Returns:
            int: status code
            dict: query result. e.g.
                {
                    "result": {
                        "task_name": "task",
                        "description": "a long description",
                        "host_num": 2,
                        "latest_execute_time": 1111111111,
                        "accept": true,
                        "takeover": false
                    }
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_task_info(data)
            LOGGER.debug("Finished getting task info.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting task info failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_task_info(self, data):
        """
        query and process task info
        Args:
            data (dict): task id info

        Returns:
            int: status code
            dict: query result
        """
        task_id = data["task_id"]
        username = data["username"]

        task_info_data = (
            self.session.query(
                Task.task_name, Task.description, Task.host_num, Task.latest_execute_time, Task.accepted, Task.takeover
            )
            .filter(Task.task_id == task_id, Task.username == username)
            .first()
        )

        if not task_info_data:
            LOGGER.debug("No data found when getting the info of task: %s." % task_id)
            return NO_DATA, {"result": {}}

        # raise exception when multiple record found
        info_dict = self._task_info_row2dict(task_info_data)
        return SUCCEED, {"result": info_dict}

    @staticmethod
    def _task_info_row2dict(row):
        task_info = {
            "task_name": row.task_name,
            "description": row.description,
            "host_num": row.host_num,
            "latest_execute_time": row.latest_execute_time,
            "accept": row.accepted,
            "takeover": row.takeover,
        }
        return task_info

    def get_task_type(self, task_id, username):
        """
        Return the type of the task, return None if check failed.

        Args:
            task_id (str): task id
            username (str): user name

        Returns:
            int
            str or None
        """
        try:
            status_code, task_type = self._get_task_type(task_id, username)
            if status_code == SUCCEED:
                LOGGER.debug("Finished getting task's type.")
            return task_type
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting task's type failed due to internal error.")
            return None

    def _get_task_type(self, task_id, username):
        """
        query task's type.
        """
        try:
            type_info = (
                self.session.query(Task.task_type).filter(Task.task_id == task_id, Task.username == username).one()
            )
        except sqlalchemy.orm.exc.NoResultFound:
            LOGGER.error("Querying type of task '%s' failed due to no data found." % task_id)
            return NO_DATA, None
        except sqlalchemy.orm.exc.MultipleResultsFound:
            LOGGER.error("Querying type of task '%s' failed due to multiple data found." % task_id)
            return DATABASE_QUERY_ERROR, None

        return SUCCEED, type_info.task_type

    def update_task_execute_time(self, task_id, cur_time):
        """
        Update task latest execute time when task is executed
        Args:
            task_id (str): task id
            cur_time (int): latest execute time

        Returns:
            int: status code
        """
        try:
            status_code = self._update_latest_execute_time(task_id, cur_time)
            if status_code != SUCCEED:
                return status_code
            self.session.commit()
            LOGGER.debug("Finished updating task's latest execute time.")
            return status_code
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Updating task's latest execute time failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def _update_latest_execute_time(self, task_id, cur_time):
        """
        update a task's latest execute time
        """
        task_info = self.session.query(Task).filter(Task.task_id == task_id).first()

        if not task_info:
            LOGGER.error("Updating latest execute time of task '%s' failed due to no data found." % task_id)
            return NO_DATA

        task_info.latest_execute_time = cur_time
        return SUCCEED

    def check_task_status(self, task_id, task_type):
        """
        check the task is open for execute or not
        Args:
            task_id (str): task id
            task_type (str): for now, 'cve fix' or 'repo set' or 'cve rollback' or 'hotpatch remove'

        Returns:
            bool
        """
        if task_type in [TaskType.CVE_FIX, TaskType.CVE_ROLLBACK, TaskType.HOTPATCH_REMOVE]:
            task_progress = self._get_cve_series_task_progress([task_id], task_type)
        elif task_type == TaskType.REPO_SET:
            task_progress = self._get_repo_task_progress([task_id])
        else:
            LOGGER.error("Unknown task type '%s' was given when checking task '%s' status." % (task_type, task_id))
            return True

        if task_progress[task_id][TaskStatus.RUNNING]:
            return False
        return True

    def query_user_email(self, username: str) -> tuple:
        """
        query user email from database by username

        Args:
            username(str)

        Returns:
            str: status_code
            str: email address
        """
        try:
            user = self.session.query(User).filter(User.username == username).one()
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("update task_cve_host table status failed.")
            return DATABASE_QUERY_ERROR, ""

        return SUCCEED, user.email


class TaskEsProxy(ElasticsearchProxy):
    def save_task_info(self, task_id, host_id, log, **kwargs):
        """
         Every time log are generated, save them to es database.

        Args:
            task_id (str): task id
            log (str): task's log

        Returns:
            int: status code
        """
        if not log:
            LOGGER.warning("task log to be inserted is empty")
            return DATABASE_INSERT_ERROR
        task_body = {"task_id": task_id, "host_id": host_id, "log": log}
        task_body.update(**kwargs)
        document_id = hash_value(str(task_id) + "_" + str(host_id))
        operation_code, exists = self.exists(TASK_INDEX, document_id=document_id)
        if not operation_code:
            LOGGER.error("Failed to query whether the task exists or not due to internal error")
            return DATABASE_INSERT_ERROR

        if exists:
            operation_code = self.update_bulk(TASK_INDEX, [{"_id": document_id, "doc": task_body}])
        else:
            operation_code = TaskEsProxy.insert(self, index=TASK_INDEX, body=task_body, document_id=document_id)

        if operation_code:
            LOGGER.debug("Finished saving task info into es.")
            return SUCCEED

        LOGGER.error("Saving task info into es failed due to internal error.")
        return DATABASE_INSERT_ERROR

    def _query_task_info_from_es(self, task_id, host_id=None, username=None, source=True):
        """
        query task's info from elasticsearch
        Args:
            task_id (str): task id
            host_id (int): host id
            username (str/None): user name, used for authorisation check
            source (bool/list): list of source

        Returns:
            bool
            dict
        """
        query_body = self._general_body()
        query_body.update({"from": 0, "size": 10000})
        query_body["query"]["bool"]["must"].append({"term": {"task_id": task_id}})
        if username:
            query_body["query"]["bool"]["must"].append({"term": {"username": username}})
        if host_id:
            query_body["query"]["bool"]["must"].append({"term": {"host_id": host_id}})

        operation_code, res = self.query(TASK_INDEX, query_body, source)
        return operation_code, res

    def get_task_log_info(self, task_id, host_id=None, username=None) -> Tuple[int, list]:
        """
        Get task's info (log) from es

        Args:
            task_id (str): task id
            username (str): user name, used for authorisation check

        Returns:
            int: status code
            list: needed task log info
        """

        operation_code, res = self._query_task_info_from_es(task_id, host_id, username, ["log"])

        if not operation_code:
            LOGGER.debug("Querying log info of task host '%s' failed due to internal error." % task_id)
            return DATABASE_QUERY_ERROR, []

        if not res["hits"]["hits"]:
            LOGGER.debug("No data found when getting log info of task '%s'." % task_id)
            return NO_DATA, []

        task_infos = [json.loads(task_info["_source"]["log"]) for task_info in res["hits"]["hits"]]

        LOGGER.debug("Querying task log succeed.")
        return SUCCEED, task_infos


class TaskProxy(TaskMysqlProxy, TaskEsProxy):
    def __init__(self, host=None, port=None):
        """
        Instance initialization

        Args:
            configuration (Config)
            host(str)
            port(int)
        """
        TaskMysqlProxy.__init__(self)
        TaskEsProxy.__init__(self, host, port)

    def delete_task(self, data):
        """
        Delete task.

        Args:
            data (dict): parameter. e.g.
                {
                    "username": "admin",
                    "task_list": []
                }

        Returns:
            int: status code
            task id: running task id list
        """
        try:
            running_task = self._delete_task(data)
            self.session.commit()
            if running_task:
                return PARTIAL_SUCCEED, running_task

            LOGGER.debug("Finished deleting task.")
            return SUCCEED, running_task
        except (SQLAlchemyError, ElasticsearchException, EsOperationError) as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Deleting task failed due to internal error.")
            return DATABASE_DELETE_ERROR, None

    def _delete_task(self, data):
        """
        Delete task's info from both mysql and es.
        Args:
            data (dict): task list info

        Returns:
            running_task: running task id list
        Raises:
            ElasticsearchException
        """
        username = data["username"]
        task_list = data["task_list"]
        deleted_task, running_task = self._delete_task_from_mysql(username, task_list)
        self._delete_task_from_es(username, deleted_task)
        return running_task

    def _delete_task_from_mysql(self, username, task_list):
        """
        Delete task from Task table in mysql, related rows in other tables will also be deleted.
        Args:
            username (str): user name
            task_list (list): task id list

        Returns:
            wait_delete_task_list: deleted task id list
            running_task_id_list: running task id list
        """
        task_query = self.session.query(Task).filter(Task.username == username, Task.task_id.in_(task_list))

        succeed_list = [row.task_id for row in task_query]
        fail_list = list(set(task_list) - set(succeed_list))
        # query running tasks
        running_tasks = (
            self.session.query(HotpatchRemoveTask.task_id)
            .filter(HotpatchRemoveTask.status == TaskStatus.RUNNING, HotpatchRemoveTask.task_id.in_(task_list))
            .union(
                self.session.query(TaskHostRepoAssociation.task_id).filter(
                    TaskHostRepoAssociation.task_id.in_(task_list), TaskHostRepoAssociation.status == TaskStatus.RUNNING
                )
            )
            .union(
                self.session.query(CveFixTask.task_id).filter(
                    CveFixTask.task_id.in_(task_list), CveFixTask.status == TaskStatus.RUNNING
                )
            )
            .all()
        )
        running_task_id_list = [task.task_id for task in running_tasks]

        if fail_list:
            LOGGER.debug("No data found when deleting the task '%s' from mysql." % fail_list)
        if running_task_id_list:
            LOGGER.warning("A running task exists, tasks id: %s." % " ".join(running_task_id_list))

        wait_delete_task_list = list(set(succeed_list) - set(running_task_id_list))
        self.session.query(Task).filter(Task.task_id.in_(wait_delete_task_list)).delete(synchronize_session=False)
        LOGGER.debug("Delete task from mysql succeed.")
        return wait_delete_task_list, running_task_id_list

    def _delete_task_from_es(self, username, task_list):
        """
        Delete task from elasticsearch's 'task' index
        Args:
            username (str): user name
            task_list (list): task id list

        Raises:
            EsOperationError
        """
        query_body = self._general_body()
        query_body["query"]["bool"]["must"].extend([{"terms": {"_id": task_list}}, {"term": {"username": username}}])

        res = TaskEsProxy.delete(self, TASK_INDEX, query_body)
        if res:
            LOGGER.debug("Delete task from elasticsearch succeed.")
            return

        raise EsOperationError("Delete task from elasticsearch failed due to internal error.")

    def get_running_task_form_task_cve_host(self) -> list:
        """
        Get all CVE repair tasks with running status under Username

        Returns:
            list: task id list
        """
        task_cve_query = (
            self.session.query(HotpatchRemoveTask).filter(HotpatchRemoveTask.status == TaskStatus.RUNNING).all()
        )
        task_id_list = [task.task_id for task in task_cve_query]
        return task_id_list

    def get_running_task_form_task_host_repo(self) -> list:
        """
        Get all repo set tasks with running status under Username

        Returns:
            list: task id list
        """
        host_repo_query = (
            self.session.query(TaskHostRepoAssociation)
            .filter(TaskHostRepoAssociation.status == TaskStatus.RUNNING)
            .all()
        )
        task_id_list = [task.task_id for task in host_repo_query]
        return task_id_list

    def get_scanning_status_and_time_from_host(self) -> list:
        """
        Get all host id and time with scanning status from the host table

        Returns:
            list: host id list
        """
        host_info_query = self.session.query(Host).filter(Host.status == HostStatus.SCANNING).all()
        host_info_list = [(host.host_id, host.last_scan) for host in host_info_query]
        return host_info_list

    def get_task_create_time(self):
        """
        Get the creation time for each running task

        Returns:
            list: Each element is a task information, including the task ID, task type, creation time
        """
        task_cve_id_list = self.get_running_task_form_task_cve_host()
        task_repo_id_list = self.get_running_task_form_task_host_repo()
        host_info_list = self.get_scanning_status_and_time_from_host()
        task_id_list = task_cve_id_list + task_repo_id_list

        task_query = self.session.query(Task).filter(Task.task_id.in_(task_id_list)).all()
        running_task_list = [(task.task_id, task.create_time) for task in task_query]
        return running_task_list, host_info_list

    def validate_cves(self, cve_id: list) -> bool:
        """
        Verifying cve validity

        Args:
            cve_id: id of the cve to be validate

        Returns:
            bool:  A return of true indicates that the validation passed
        """

        try:
            exists_cve_count = (
                self.session.query(CveHostAssociation.cve_id)
                .filter(CveHostAssociation.cve_id.in_(cve_id))
                .distinct()
                .count()
            )

            return True if exists_cve_count == len(cve_id) else False
        except SQLAlchemyError as error:
            LOGGER.error(error)
            return False

    def validate_hosts(self, host_id: list, username=None) -> bool:
        """
        Verifying host validity

        Args:
            host_id: id of the host to be validate
            username: system user name

        Returns:
            bool:  A return of true indicates that the validation passed
        """
        try:
            exists_host_query = self.session.query(Host).filter(Host.host_id.in_(host_id))
            if username:
                exists_host_query.filter(Host.user == username)
            exists_host_count = exists_host_query.count()
            return True if exists_host_count == len(host_id) else False
        except SQLAlchemyError as error:
            LOGGER.error(error)
            return False

    def _query_task_basic_info(self, task_id: str) -> sqlalchemy.orm.Query:
        """
        query basic task info

        Args:
            task_id

        Returns:
            sqlalchemy.orm.Query
        """
        task_query = self.session.query(
            Task.task_id, Task.task_name, Task.task_type, Task.check_items, Task.accepted, Task.takeover, Task.fix_type
        ).filter(Task.task_id == task_id)
        return task_query

    def get_task_hosts(self, task_id) -> tuple:
        """
        Getting hosts of the task, only support cve fix task or hotpatch remove task or cve rollback task

        Args:
            task_id: task id

        Returns:
            status_code: str
            hosts: list
        """

        try:
            hosts = self._get_task_hosts(task_id)
            if not hosts:
                return NO_DATA, hosts
            LOGGER.debug("Finished getting host info of task.")
            return SUCCEED, hosts
        except SQLAlchemyError as error:
            LOGGER.error(error)
            return DATABASE_QUERY_ERROR, []

    def _get_task_hosts(self, task_id: str) -> list:
        hosts = []
        task_info = self.session.query(Task).filter(Task.task_id == task_id).first()
        if not task_info:
            return hosts
        if task_info.task_type == TaskType.HOTPATCH_REMOVE:
            hosts = (
                self.session.query(HotpatchRemoveTask.host_id)
                .filter(HotpatchRemoveTask.task_id == task_id)
                .group_by(HotpatchRemoveTask.host_id)
                .all()
            )
        elif task_info.task_type == TaskType.CVE_FIX:
            hosts = (
                self.session.query(CveFixTask.host_id)
                .filter(CveFixTask.task_id == task_id)
                .group_by(CveFixTask.host_id)
                .all()
            )
        elif task_info.task_type == TaskType.CVE_ROLLBACK:
            hosts = (
                self.session.query(CveRollbackTask.host_id)
                .filter(CveRollbackTask.task_id == task_id)
                .group_by(CveRollbackTask.host_id)
                .all()
            )
        return [host.host_id for host in hosts]
