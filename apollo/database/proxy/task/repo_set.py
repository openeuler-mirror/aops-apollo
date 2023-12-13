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
from elasticsearch import ElasticsearchException
from sqlalchemy.exc import SQLAlchemyError
from vulcanus.database.helper import sort_and_page
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import (
    DATABASE_INSERT_ERROR,
    NO_DATA,
    DATABASE_QUERY_ERROR,
    DATABASE_UPDATE_ERROR,
    SUCCEED,
    PARAM_ERROR,
)

from apollo.conf.constant import REPO_FILE, TaskStatus, TaskType
from apollo.database.table import (
    Repo,
    Task,
    TaskHostRepoAssociation,
    Host,
)
from apollo.function.customize_exception import EsOperationError
from apollo.database.proxy.task.base import TaskProxy


class RepoSetProxy(TaskProxy):
    def generate_repo_task(self, data):
        """
        For generating, save repo task basic info to mysql, init task info in es.

        Args:
            data (dict): e.g.
                {
                    "username": "admin"
                    "task_id": "",
                    "task_name": "",
                    "task_type": "",
                    "description": "",
                    "repo_name": "",
                    "create_time": 1,
                    "info": [
                        {
                            "host_id": ""
                        }
                    ]
                }

        Returns:
            int: status code
        """
        try:
            status_code = self._gen_repo_task(data)
            if status_code != SUCCEED:
                return status_code
            self.session.commit()
            LOGGER.debug("Finished generating repo task.")
            return SUCCEED
        except (SQLAlchemyError, ElasticsearchException, EsOperationError) as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Generate repo task failed due to internal error.")
            return DATABASE_INSERT_ERROR

    def _gen_repo_task(self, data):
        """
        generate repo task. Process data, then:
        1. insert task basic info into mysql Task table
        2. insert host and repo's relationship and setting status into mysql
           TaskHostRepoAssociation table
        3. insert task's id and username into elasticsearch
        Args:
            data (dict): repo task info

        Raises:
            EsOperationError
        """
        task_id = data["task_id"]
        repo_name = data.pop("repo_name")

        task_repo_host_rows = []
        host_ids = list(set([host["host_id"] for host in data.pop("info")]))
        host_list = (
            self.session.query(Host.host_id, Host.host_name, Host.host_ip).filter(Host.host_id.in_(host_ids)).all()
        )
        if len(host_list) != len(host_ids):
            return PARAM_ERROR

        for host in host_list:
            host_info = dict(host_id=host.host_id, host_name=host.host_name, host_ip=host.host_ip)
            task_repo_host_rows.append(self._task_repo_host_row_dict(task_id, repo_name, host_info))

        # insert data into mysql tables
        data["host_num"] = len(host_ids)
        self._insert_repo_task_tables(data, task_repo_host_rows)
        return SUCCEED

    @staticmethod
    def _task_repo_host_row_dict(task_id, repo_name, host_info):
        """
        insert repo setting into TaskHostRepoAssociation table
        """
        return {
            "task_id": task_id,
            "repo_name": repo_name,
            "host_id": host_info["host_id"],
            "host_name": host_info["host_name"],
            "host_ip": host_info["host_ip"],
            "status": TaskStatus.UNKNOWN,
        }

    def _insert_repo_task_tables(self, task_data, task_repo_host_rows):
        """
        insert data into two tables when generating repo task.
        Task table need commit after add, otherwise following insertion will fail due to
        task.task_id foreign key constraint.
        Args:
            task_data (dict): task basic info for Task table
            task_repo_host_rows (list): list of row dict for TaskHostRepoAssociation table

        Raises:
            SQLAlchemyError
        """
        self.session.add(Task(**task_data))
        self.session.commit()

        try:
            self.session.bulk_insert_mappings(TaskHostRepoAssociation, task_repo_host_rows)
        except SQLAlchemyError:
            self.session.rollback()
            self.session.query(Task).filter(Task.task_id == task_data["task_id"]).delete()
            self.session.commit()
            raise

    def get_repo_task_info(self, data):
        """
        Get repo task info.

        Args:
            data (dict): e.g.
                {
                    "username": "admin",
                    "task_id": "",
                    "page": 1,
                    "per_page": 10,
                    "filter": {
                        "host_name": "",
                        "status": [],
                        "host_id": ""
                    }
                }

        Returns:
            int: status code
            dict. e.g.
                {
                    "result": [
                        {
                            "host_id": "id1",
                            "host_name": "host1",
                            "host_ip": "id1",
                            "repo_name": "repo1",
                            "status": "running"
                        }
                    ],
                    "total_count": 1,
                    "total_page": 1
                }
        """
        result = {}
        try:
            result = self._get_processed_repo_task(data)
            LOGGER.debug("Finished getting repo task info.")
            return SUCCEED, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting repo task info failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_repo_task(self, data):
        """
        query and process repo task info
        Args:
            data (dict): query condition

        Returns:
            int: status code
            dict
        """
        result = {"total_count": 0, "total_page": 1, "result": []}

        task_id = data["task_id"]
        filter_dict = data.get("filter")
        filters = self._get_repo_task_filters(filter_dict)
        repo_task_query = self._query_repo_task(data["username"], task_id, filters)

        total_count = len(repo_task_query.all())
        # NO_DATA code is NOT returned because no data situation here is normal
        # with filter
        if not total_count:
            return result

        page = data.get('page')
        per_page = data.get('per_page')
        processed_query, total_page = sort_and_page(repo_task_query, None, None, per_page, page)

        result['result'] = self._repo_task_info_row2dict(processed_query)
        result['total_page'] = total_page
        result['total_count'] = total_count

        return result

    def _query_repo_task(self, username, task_id, filters):
        """
        query needed repo task's host info
        Args:
            username (str): user name of the request
            task_id (str): task id
            filters (set): filter given by user

        Returns:
            sqlalchemy.orm.query.Query. row structure:
                {
                    "host_id": "id1",
                    "host_name": "name1",
                    "host_ip": "ip1",
                    "repo_name": "repo1",
                    "status": "unset"
                }
        """
        task_repo_query = (
            self.session.query(
                TaskHostRepoAssociation.host_id,
                TaskHostRepoAssociation.host_name,
                TaskHostRepoAssociation.host_ip,
                TaskHostRepoAssociation.repo_name,
                TaskHostRepoAssociation.status,
            )
            .join(Task, Task.task_id == TaskHostRepoAssociation.task_id)
            .filter(Task.username == username, TaskHostRepoAssociation.task_id == task_id)
            .filter(*filters)
        )

        return task_repo_query

    @staticmethod
    def _get_repo_task_filters(filter_dict):
        """
        Generate filters to filter repo task's host info
        Args:
            filter_dict(dict): filter dict to filter repo task's host info, e.g.
                {
                    "host_name": "name1",
                    "status": [],
                    "host_id":""
                }

        Returns:
            set
        """
        filters = set()
        if not filter_dict:
            return filters

        if filter_dict.get("host_name"):
            filters.add(TaskHostRepoAssociation.host_name.like("%" + filter_dict["host_name"] + "%"))
        if filter_dict.get("status"):
            filters.add(TaskHostRepoAssociation.status.in_(filter_dict["status"]))
        if filter_dict.get("host_id"):
            filters.add(TaskHostRepoAssociation.host_id == filter_dict["host_id"])
        return filters

    @staticmethod
    def _repo_task_info_row2dict(rows):
        result = []
        for row in rows:
            host_info = {
                "host_id": row.host_id,
                "host_name": row.host_name,
                "host_ip": row.host_ip,
                "repo_name": row.repo_name,
                "status": row.status,
            }
            result.append(host_info)
        return result

    def set_repo_status(self, task_id, host_list, status):
        """
        Everytime a repo setting task will be executed or has been completed,
        update the related status.

        Args:
            task_id (str)
            host_list (list): host id list, can be empty, which means all host.
            status (str): can be "set", "unset", "running", "unknown"
            ('unknown' when task has some error, but prefer using 'fix_task_status' in this case)

        Returns:
            int: status code
        """
        try:
            self._update_repo_host_status(task_id, host_list, status)
            self.session.commit()
            LOGGER.debug("Finished updating repo host status.")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Updating repo host status failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def _update_repo_host_status(self, task_id, host_list, status):
        """
        update a host's repo setting status of a repo task
        """
        filters = {TaskHostRepoAssociation.task_id == task_id}
        if host_list:
            filters.add(TaskHostRepoAssociation.host_id.in_(host_list))

        status_query = self.session.query(TaskHostRepoAssociation).filter(*filters)
        status_query.update({TaskHostRepoAssociation.status: status}, synchronize_session=False)

    def get_repo_info(self, data: dict):
        """
        GET repo information

        Args:
            data(dict): e.g.
                {
                    "repo_name": "repo1",
                    "username": "admin"
                }
        Returns:
            stattus_code: State of the query
            repo(dict): repo info e.g
                {
                    "repo_id":"",
                    "repo_name":"",
                    "repo_data":"",
                    "repo_attr":""
                }
        """
        try:
            status_code, repo_info = self._get_repo_info(data.get("repo_name"), data.get("username"))
            LOGGER.debug("Finished getting repo info.")
            return status_code, repo_info
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting repo info failed due to internal error.")
            return DATABASE_QUERY_ERROR, None

    def _get_repo_info(self, repo_name, username):
        """
        Query repo info
        """
        filters = {Repo.repo_name == repo_name}
        if username:
            filters.add(Repo.username == username)

        query_repo_info = (
            self.session.query(Repo.repo_id, Repo.repo_name, Repo.repo_attr, Repo.repo_data).filter(*filters).first()
        )
        if not query_repo_info:
            LOGGER.debug(f"Repo information does not exist: {repo_name}.")
            return NO_DATA, None
        repo_info = dict(
            repo_name=query_repo_info.repo_name,
            repo_data=query_repo_info.repo_data,
            repo_attr=query_repo_info.repo_attr,
            repo_id=query_repo_info.repo_id,
        )
        return SUCCEED, repo_info

    def get_repo_set_task_template(self, task_id: str, username: str):
        """
        Get the task template set by repo

        Args:
            task_id: id of the task set by repo
            username: user name
        Returns:
            status_code: State of the query
            task: task info
        """
        # query task info

        status_code, task_info = self.get_task_info(data=dict(task_id=task_id, username=username))
        if status_code != SUCCEED:
            LOGGER.debug(f"Getting task info failed, task id: {task_id}.")
            return status_code, None
        # query task host
        status_code, host_info = self.get_repo_task_info(data=dict(username=username, task_id=task_id))
        if status_code != SUCCEED:
            LOGGER.debug(f"Getting repo task info failed, task id: {task_id}.")
            return status_code, None
        repo_name = host_info["result"][-1]["repo_name"]

        # query repo info
        status_code, repo_info = self.get_repo_info(dict(repo_name=repo_name, username=username))
        if status_code != SUCCEED:
            LOGGER.debug(f"Getting repo info failed, repo name: {repo_name}.")
            return status_code, None
        task_template = {
            "task_id": task_id,
            "task_name": task_info["result"]["task_name"],
            "task_type": TaskType.REPO_SET,
            "check_items": [],
            "repo_info": {"name": repo_name, "repo_content": repo_info["repo_data"], "dest": REPO_FILE},
            "total_hosts": [host["host_id"] for host in host_info["result"]],
        }

        return SUCCEED, task_template

    def update_repo_host_status_and_host_reponame(self, data: dict, hosts_id_list: list):
        """
        After repo is successfully set, update the host status and set repo name to the host name

        Args:
            data: e.g
                {
                    "task_id":"",
                    "status":"",
                    "repo_name":
                }

        Returns:
            status_code: update state
        """
        try:
            self._update_repo_host_status(data["task_id"], hosts_id_list, data["status"])
            if data["status"] == TaskStatus.SUCCEED:
                self._update_host_repo(data["repo_name"], hosts_id_list)
            self.session.commit()
            LOGGER.debug("Finished setting repo name to hosts and update repo host state when task finished .")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Setting repo name to hosts and update repo host state failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def _update_host_repo(self, repo_name, host_list):
        """
        set repo name to relative hosts
        """
        self.session.query(Host).filter(Host.host_id.in_(host_list)).update(
            {Host.repo_name: repo_name}, synchronize_session=False
        )

    def get_task_repo_result(self, data):
        """
        Get the result of each host in the task, in addition to basic info of the task.

        Args:
            data (dict): parameter. e.g.
                {
                    "username": "admin",
                    "task_id": "",
                    "host_list": []  // if empty, return all host's result
                }

        Returns:
            int: status code
            list: query result. e.g.
                [{
                "task_id": "90d0a61e32a811ee8677000c29766160",
                "host_id": "2",
                "latest_execute_time": "1691465474",
                "task_type": "repo set",
                "task_result": {
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                        ],
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "log": "operate success",
                    "repo": "2203sp2",
                    "status": "fail"
                }
            }]

        """
        result = {}
        try:
            status_code, result = self._get_repo_task_result(data)
            LOGGER.debug("Finished getting repo task result.")
            return status_code, result
        except (ElasticsearchException, KeyError) as error:
            LOGGER.error(error)
            LOGGER.error("Getting repo task result failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_repo_task_result(self, data):
        """
        query repo task result from mysql and es.
        """
        username = data["username"]
        task_id = data["task_id"]
        host_list = data["host_list"]
        # task log is in the format of returned dict of func
        status_code, task_log = self.get_task_log_info(task_id=task_id, username=username)
        if status_code != SUCCEED:
            return status_code, []

        if host_list and task_log:
            task_log = [log for log in task_log if log["host_id"] in host_list]

        return SUCCEED, task_log
