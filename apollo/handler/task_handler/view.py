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
Description: Handle about task related operation
"""
import time
import uuid
from typing import Dict, List, Tuple

from celery import group
from celery.exceptions import CeleryError
from flask import g, request
from vulcanus.conf.constant import UserRoleType
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import (
    DATABASE_QUERY_ERROR,
    DATABASE_UPDATE_ERROR,
    PARAM_ERROR,
    PARTIAL_SUCCEED,
    PERMESSION_ERROR,
    REPEAT_TASK_EXECUTION,
    SUCCEED,
    TASK_EXECUTION_FAIL,
)
from vulcanus.restful.response import BaseResponse

from apollo.conf import cache, celery_client
from apollo.conf.constant import HostStatus, TaskChannel, TaskType
from apollo.cron.notification import EmailNoticeManager
from apollo.database.proxy.host import HostProxy
from apollo.database.proxy.task.base import TaskMysqlProxy, TaskProxy
from apollo.database.proxy.task.cve_fix import CveFixTaskProxy
from apollo.database.proxy.task.cve_rollback import CveRollbackTaskProxy
from apollo.database.proxy.task.hotpatch_remove import HotpatchRemoveProxy
from apollo.database.proxy.task.repo_set import RepoSetProxy
from apollo.database.proxy.task.scan import ScanProxy
from apollo.function.schema.host import ScanHostSchema
from apollo.function.schema.task import *
from apollo.function.schema.task import GetHotpatchRemoveTaskCveInfoSchema
from apollo.function.utils import query_user_hosts
from apollo.handler.task_handler.callback.cve_fix import CveFixCallback
from apollo.handler.task_handler.callback.cve_rollback import CveRollbackCallback
from apollo.handler.task_handler.callback.cve_scan import CveScanCallback
from apollo.handler.task_handler.callback.hotpatch_remove import HotpatchRemoveCallback
from apollo.handler.task_handler.callback.repo_set import RepoSetCallback
from apollo.handler.task_handler.manager.cve_fix_manager import CveFixManager
from apollo.handler.task_handler.manager.cve_rollback_manager import CveRollbackManager
from apollo.handler.task_handler.manager.hotpatch_remove_manager import HotpatchRemoveManager
from apollo.handler.task_handler.manager.repo_manager import RepoManager
from apollo.handler.task_handler.manager.scan_manager import ScanManager


class VulScanHost(BaseResponse):
    """
    Restful interface for scanning hosts
    """

    @staticmethod
    def _verify_param(query_host_list, actual_host_list):
        """
        Verify the host list is whether valid

        Args:
            query_host_list (list): input host id list
            actual_host_list (list): host info list queried from database according
                                     to the input host id list

        Returns:
            bool
        """
        # when scan the whole host, the input host id list is empty,
        # but the actual host list should not be empty.
        host_list = []
        for host in actual_host_list:
            if host["status"] == HostStatus.SCANNING:
                return False
            host_list.append(host["host_id"])

        if not query_host_list:
            if not actual_host_list:
                return False

            return True

        # check whether the host ids are corresponding
        if len(query_host_list) != len(actual_host_list):
            return False

        for ele in query_host_list:
            if ele not in host_list:
                return False

        return True

    def _handle(self, proxy: ScanProxy, args):
        """
        Generate scan task according to host info, and run it.

        Args:
            proxy(TaskMysqlProxy): Database connection object
            args (dict): request parameter

        Returns:
            int: status code
        """
        # verify host id
        host_list = args.get("host_list")
        query_fields = ["host_id", "host_ip", "host_name", "status", "ssh_user", "ssh_port", "pkey"]
        host_info_list: List[dict] = query_user_hosts(host_list=host_list, fields=query_fields)
        if not self._verify_param(host_list, host_info_list):
            LOGGER.error("There are some host in %s that can not be scanned.", host_list)
            return PARAM_ERROR

        task_id = str(uuid.uuid1()).replace("-", "")
        # init status
        current_cluster_info = cache.location_cluster
        if not current_cluster_info:
            LOGGER.error("Failed to get current cluster info.")
            return DATABASE_QUERY_ERROR

        cve_scan_manager = ScanManager(task_id, proxy, host_info_list, current_cluster_info.get("cluster_id"))
        cve_scan_manager.create_task()
        if not cve_scan_manager.pre_handle():
            return DATABASE_UPDATE_ERROR
        # run the task
        status = cve_scan_manager.execute_task()

        return status

    @BaseResponse.handle(schema=ScanHostSchema, proxy=ScanProxy)
    def post(self, callback: HostProxy, **params):
        """
        Scan host's cve

        Args:
            host_list (list): host id list

        Returns:
            dict: response body

        """
        return self.response(self._handle(callback, params))


class VulGetTaskList(BaseResponse):
    """
    Restful interface for getting task(cve fixing or repo setting) list.
    """

    @BaseResponse.handle(schema=GetTaskListSchema, proxy=TaskMysqlProxy)
    def post(self, callback: TaskMysqlProxy, **params):
        """
        Args:
            sort (str, optional): can be chosen from host_num, create_time.
            direction (str, optional): asc or desc. Defaults to asc.
            page (int, optional): current page in web.
            per_page (int, optional): number of items in each page.
            filter (dict, optional): filter condition.

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": "operation succeed",
                    "total_count": 1,
                    "total_page": 1,
                    "result": [
                        {
                            "task_id": "id1",
                            "task_name": "task1",
                            "task_type": "cve",
                            "description": "fix cve CVE-2021-29535",
                            "host_num": 2,
                            "create_time": 161111112
                        }
                    ]
                }
        """
        cluster_info = cache.get_user_clusters()

        user_role = cache.user_role
        if not user_role:
            return self.response(code=PERMESSION_ERROR, message="Failed to query user permission information!")

        if user_role == UserRoleType.NORMAL:
            userinfo_list = cache.get_user_cluster_private_key

            all_username_list = [userinfo.get("cluster_username") for _, userinfo in userinfo_list.items()]
            all_username_list.append(g.username)
            if params.get("filter"):
                params["filter"]["username_list"] = all_username_list
            else:
                params["filter"] = {"username_list": all_username_list}
        status_code, result = callback.get_task_list(params, cluster_info)
        return self.response(code=status_code, data=result)


class VulGetTaskProgress(BaseResponse):
    """
    Restful interface for getting task progress.
    """

    @BaseResponse.handle(schema=GetTaskProgressSchema, proxy=TaskMysqlProxy)
    def post(self, callback: TaskMysqlProxy, **params):
        """
        Args:

            task_list (list): task id list, shall not be empty

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": "",
                    "result": {
                        "task1": {
                            "succeed": 1,
                            "fail": 0,
                            "running": 11,
                            "unknown": 0
                        }
                    }
                }
        """
        status_code, result = callback.get_task_progress(params)
        return self.response(code=status_code, data=result)


class VulGetTaskInfo(BaseResponse):
    """
    Restful interface for getting basic info of a task.
    """

    @BaseResponse.handle(schema=GetTaskInfoSchema, proxy=TaskMysqlProxy)
    def get(self, callback: TaskMysqlProxy, **params):
        """
        Args:
            task_id (str): task id

        Returns:
            dict: response body, e,g,
                {
                    "code": 200,
                    "msg": "",
                    "result": {
                        "description": "xxxxx",
                        "host_num": 1,
                        "latest_execute_time": 1690432440,
                        "task_name": "CVE-xxxx-xxxx",
                        "accept": true,
                        "takeover": false
                    }
                }
        """
        cluster_info = cache.get_user_clusters()

        if len(cluster_info) == 0:
            LOGGER.debug("Failed to query valid user permission information!")
            return self.response(code=PERMESSION_ERROR, data={})

        status_code, result = callback.get_task_info(params.get("task_id"), cluster_info)
        return self.response(code=status_code, data=result)


class VulGenerateCveFixTask(BaseResponse):
    """
    Restful interface for generating a cve fix task.
    """

    def _query_host_info(self, host_list):
        """"""
        result = {}
        query_fields = ["host_id", "host_ip", "host_name"]
        host_info_list = query_user_hosts(host_list, query_fields)

        if len(host_info_list) != len(host_list):
            LOGGER.error("Failed to get host info!")
            return PARAM_ERROR, result
        for host in host_info_list:
            result[host.get("host_id")] = dict(
                host_id=host.get("host_id"), host_ip=host.get("host_ip"), host_name=host.get("host_name")
            )

        return SUCCEED, result

    def _handle(self, params, proxy):
        """
        handle for generate cve fix task

        Args:
            params (dict): task info including cve id and related host info
            proxy (CveFixTaskProxy): cve fix task proxy

        Returns:
            tuple: (status_code, result)
        """
        cve_ids = [cve["cve_id"] for cve in params["info"]]
        if not proxy.validate_cves(cve_id=list(set(cve_ids))):
            return PARAM_ERROR, {}

        status_code, host_info = self._query_host_info(
            list(set([host["host_id"] for task_info in params.get("info") for host in task_info["host_info"]]))
        )
        if status_code != SUCCEED:
            LOGGER.error("Failed to get host info!")
            return status_code, {}

        current_cluster_info = cache.location_cluster
        if not current_cluster_info:
            LOGGER.debug("Failed to get current cluster id")
            return DATABASE_QUERY_ERROR, {}

        params.update(
            {"cluster_id": current_cluster_info.get("cluster_id"), "host_dict": host_info, "username": g.username}
        )

        status_code, task = proxy.generate_cve_task(params)
        if status_code != SUCCEED:
            LOGGER.error("Generate cve fix task fail, fail to save task info to database.")

        return status_code, task

    @BaseResponse.handle(schema=GenerateCveTaskSchema, proxy=CveFixTaskProxy)
    def post(self, callback: CveFixTaskProxy, **params):
        """
        Args:
            task_name (str)
            description (str)
            check_items (str)
            info (list): task info including cve id and related host info

        Returns:
            dict: response body, e.g.
                {
                    "code": "200",
                    "data": [
                        {
                            "task_id": "8878b35288df11eeb0815254001a9e0d",
                            "fix_way": "hotpatch/coldpatch"
                        }
                    ],
                    "label": "Succeed",
                    "message": "operation succeed"
                }
        """
        status, task = self._handle(params, callback)
        return self.response(code=status, data=task)


class VulGetCveFixTaskInfo(BaseResponse):
    """
    Restful interface for getting the info of a task which fixes cve.
    """

    @BaseResponse.handle(schema=GetCveFixTaskInfoSchema, proxy=CveFixTaskProxy)
    def post(self, callback: CveFixTaskProxy, **params):
        """
        Args:
            task_id (str)
            page (int, optional): current page in web.
            per_page (int, optional): number of items in each page.
            filter (dict, optional): filter condition.

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": "",
                    "result": [
                        {
                            "cve_id": "cve-11-1",
                            "package": "",
                            ""
                        }
                    ]
                }

        """
        status_code, data = callback.get_cve_task_info(params)
        return self.response(code=status_code, data=data)


class VulGetHotpatchRemoveTaskHostCveStatus(BaseResponse):
    """
    Restful interface for getting host status in the task which fixes cve.
    """

    @BaseResponse.handle(schema=GetHotpatchRemoveTaskHostCveStatusSchema, proxy=HotpatchRemoveProxy)
    def post(self, callback: HotpatchRemoveProxy, **params):
        """
        Args:
            task_id (str): task id
            cve_list (list): cve id list

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": "",
                    "result": {
                        "cve1": [
                            {
                                "host_id": 1,
                                "host_name": "name1",
                                "host_ip": "ip1",
                                "status": "running"
                            }
                        ]
                    }
                }
        """
        status_code, data = callback.get_hotpatch_remove_task_host_cve_status(params)
        return self.response(code=status_code, data=data)


class VulGetCveFixTaskResult(BaseResponse):
    """
    Restful interface for getting a CVE task's result.
    """

    @BaseResponse.handle(schema=GetTaskResultSchema, proxy=CveFixTaskProxy)
    def post(self, callback: CveFixTaskProxy, **params):
        """
        Args:
            task_id (str): task id
            cve_list (list): cve id list

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": "",
                    "result": {
                        "task_id": "1",
                        "task_type": "cve",
                        "latest_execute_time": 11,
                        "task_result": [
                            {
                                "host_id": 1,
                                "host_name": "name",
                                "host_ip": "1.1.1.1",
                                "status": "fail",
                                "check_items": [
                                    {
                                        "item": "check network",
                                        "result": True
                                    }
                                ],
                                "cves": [
                                    {
                                        "cve_id": "cve-11-1",
                                        "log": "",
                                        "result": "unfixed"
                                    }
                                ]
                            }
                        ]
                    }
                }

        """
        status_code, data = callback.get_task_cve_result(params)
        return self.response(code=status_code, data=data)


class VulGenerateRepoTask(BaseResponse):
    """
    Restful interface for generating a task which sets repo for host.
    """

    @staticmethod
    def _query_host_info(host_list: List[int]) -> Tuple[str, list]:
        """
        query host info from host service

        Args:
            host_list: List

        Returns:
            Tuple[str, list]
        """
        query_fields = ["host_id", "host_ip", "host_name"]
        data = query_user_hosts(host_list=host_list, fields=query_fields)
        if len(data) != len(host_list):
            return PARAM_ERROR, []
        return SUCCEED, data

    @BaseResponse.handle(schema=GenerateRepoTaskSchema, proxy=RepoSetProxy)
    def post(self, callback: RepoSetProxy, **params):
        """
        Args:
            task_name (str)
            description (str)
            repo_name (str)
            info (list): task dict including host info and repo id

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": "",
                    "data": {"task_id": "1"}
                }
        """
        current_cluster_info = cache.location_cluster
        if not current_cluster_info:
            LOGGER.error(
                "Generate repo setting task fail due to the failure in querying the current cluster information"
            )
            return self.response(code=DATABASE_QUERY_ERROR)

        task_id = str(uuid.uuid1()).replace("-", "")
        task_info = dict(
            task_id=task_id,
            task_name=params.get("task_name"),
            description=params.get("description"),
            task_type=TaskType.REPO_SET,
            create_time=int(time.time()),
            repo_id=params.get("repo_id"),
            cluster_id=current_cluster_info.get("cluster_id"),
            username=g.username,
        )
        data = dict(task_id=task_id)
        status, host_info = self._query_host_info(params.get("host_list"))
        if status != SUCCEED:
            LOGGER.error("Failed to query host info!")
            return self.response(code=status)

        # save task info to database
        status_code = callback.generate_repo_task(task_info, host_info)
        if status_code != SUCCEED:
            LOGGER.error("Generate repo setting task fail.")
            data = None
        return self.response(code=status_code, data=data)


class VulGetRepoTaskInfo(BaseResponse):
    """
    Restful interface for getting the info of a task which sets repo.
    """

    @BaseResponse.handle(schema=GetRepoTaskInfoSchema, proxy=RepoSetProxy)
    def post(self, callback: RepoSetProxy, **params):
        """
        Args:
            task_id (str)
            page (int, optional): current page in web
            per_page (int, optional): host number of each page
            filter (dict, optional): filter condition

        Returns:
            dict: response body
        """
        cluster_info = cache.get_user_clusters()
        if not cluster_info:
            return self.response(code=PERMESSION_ERROR, message="Failed to query valid user permission information!")

        params["cluster_id_list"] = cluster_info.keys()
        status_code, data = callback.get_repo_task_info(params)
        return self.response(code=status_code, data=data)


class VulGetRepoTaskResult(BaseResponse):
    """
    Restful interface for getting the result of a task which sets repo.
    """

    @BaseResponse.handle(schema=GetRepoTaskResultSchema, proxy=RepoSetProxy)
    def post(self, callback: RepoSetProxy, **params):
        """
        Args:
            task_id (str)
            host_list (list): host id list

        Returns:
            dict: response body

        """
        status_code, data = callback.get_task_repo_result(params)
        return self.response(code=status_code, data=data)


class VulExecuteTask(BaseResponse):
    """
    Restful interface for executing task.
    """

    type_map = {
        TaskType.CVE_FIX: "_handle_cve_fix",
        TaskType.REPO_SET: "_handle_repo_set",
        TaskType.HOTPATCH_REMOVE: "_handle_hotpatch_remove",
        TaskType.CVE_ROLLBACK: "_handle_cve_rollback",
    }

    @staticmethod
    def _handle_cve_fix(args: Dict) -> int:
        """
        Handle cve task

        Args:
            args (dict)

        Returns:
            int: status code
        """
        task_id = args["task_id"]
        with CveFixTaskProxy() as cve_fix_proxy:
            manager = CveFixManager(cve_fix_proxy, task_id)
            manager.token = args["token"]
            status_code = manager.create_task()
            if status_code != SUCCEED:
                return status_code

            if not manager.pre_handle():
                return DATABASE_UPDATE_ERROR

            return manager.execute_task()

    @staticmethod
    def _handle_cve_rollback(args: Dict) -> int:
        """
        Handle cve rollback task

        Args:
            args (dict)

        Returns:
            int: status code
        """
        task_id = args["task_id"]
        with CveRollbackTaskProxy() as cve_rollback_proxy:
            manager = CveRollbackManager(cve_rollback_proxy, task_id)
            manager.token = args["token"]
            status_code = manager.create_task()
            if status_code != SUCCEED:
                return status_code

            if not manager.pre_handle():
                return DATABASE_UPDATE_ERROR

            return manager.execute_task()

    @staticmethod
    def _handle_repo_set(args):
        """
        Handle repo set task

        Args:
            args (dict)

        Returns:
            int: status code
        """
        with RepoSetProxy() as repo_set_proxy:
            repo_manager = RepoManager(repo_set_proxy, args["task_id"])

            repo_manager.token = args["token"]
            status_code = repo_manager.create_task()
            if status_code != SUCCEED:
                return status_code

            if not repo_manager.pre_handle():
                return DATABASE_UPDATE_ERROR

            # After several check, run the task in a thread
            return repo_manager.execute_task()

    @staticmethod
    def _handle_hotpatch_remove(args):
        """
        Handle hotpatch remove task

        Args:
            args (dict)

        Returns:
            int: status code
        """
        task_id = args["task_id"]
        with HotpatchRemoveProxy() as hotpatch_proxy:
            manager = HotpatchRemoveManager(hotpatch_proxy, task_id)
            manager.token = args["token"]
            status_code = manager.create_task()
            if status_code != SUCCEED:
                return status_code

            if not manager.pre_handle():
                return DATABASE_UPDATE_ERROR

            # run the task in a thread
            return manager.execute_task()

    def _handle(self, proxy: TaskProxy, args):
        """
        Handle executing task, now support cve and repo.

        Args:
            args (dict): request parameter

        Returns:
            int: status code
        """
        args["token"] = request.headers.get("access-token")

        cluster_info = cache.get_user_clusters()
        if cluster_info is None:
            return TASK_EXECUTION_FAIL

        # verify the task:
        # 1.belongs to the user;
        # 2.task type is supported.
        task_type = proxy.get_task_type(args["task_id"], cluster_info.keys())
        if task_type is None or task_type not in self.type_map.keys():
            return PARAM_ERROR
        LOGGER.debug(task_type)

        if not proxy.check_task_status(args["task_id"], task_type):
            return REPEAT_TASK_EXECUTION

        func_name = self.type_map[task_type]
        func = getattr(self, func_name)

        return func(args)

    @BaseResponse.handle(schema=ExecuteTaskSchema, proxy=TaskProxy)
    def post(self, callback: TaskProxy, **params):
        """
        Args:
            task_id (str)

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": ""
                }
        """
        return self.response(self._handle(callback, params))


class VulDeleteTask(BaseResponse):
    """
    Restful interface for deleting tasks.
    """

    @staticmethod
    def _handle(task_proxy: TaskProxy, args):
        status_code, running_tasks = task_proxy.delete_task(args)
        if status_code == PARTIAL_SUCCEED:
            LOGGER.warning("A running task has not been deleted, task id: %s." % " ".join(running_tasks))

        return status_code, dict(running_task=running_tasks)

    @BaseResponse.handle(schema=DeleteTaskSchema, proxy=TaskProxy)
    def delete(self, callback: TaskProxy, **params):
        """
        Args:
            task_list (list): task id list

        Returns:
            dict: response body
        """
        status_code, data = self._handle(callback, params)
        return self.response(code=status_code, data=data)


class VulCveFixTaskCallback(BaseResponse):
    """
    Restful interface for cve fix callback.
    """

    @staticmethod
    def _handle(proxy, args):
        """
        Handle cve fix callback.

        Args:
            args (dict): request parameter

        Returns:
            int: status code
        """

        return CveFixCallback(proxy).callback(args)

    @BaseResponse.handle(schema=CveFixCallbackSchema, proxy=CveFixTaskProxy)
    def post(self, callback: CveFixTaskProxy, **params):
        """
        Args:
            task_id (str)
            host_id (int)
            cves (dict)

        Returns:
            dict: response body
        """
        return self.response(self._handle(callback, params))


class VulRepoSetTaskCallback(BaseResponse):
    """
    Restful interface for set repo callback.
    """

    @BaseResponse.handle(schema=RepoSetCallbackSchema, proxy=RepoSetProxy)
    def post(self, callback: RepoSetProxy, **params):
        """
        Args:
            host_id (str)
            status (str)
            task_id (str)
            repo_name (str)

        Returns:
            dict: response body
        """
        return self.response(RepoSetCallback(callback).callback(params))


class VulCveScanTaskCallback(BaseResponse):
    """
    Restful interface for cve scan callback.
    """

    @BaseResponse.handle(schema=CveScanCallbackSchema, proxy=ScanProxy)
    def post(self, callback: ScanProxy, **params):
        """
        Args:
            host_id (str)
            status (str)
            task_id (str)
            repo_name (str)

        Returns:
            dict: response body
        """
        return self.response(code=CveScanCallback(callback).callback(params))


class VulCveRollbackTaskCallback(BaseResponse):
    """
    Restful interface for cve rollback callback.
    """

    @staticmethod
    def _handle(proxy: CveRollbackTaskProxy, args):
        """
        Handle cve rollback callback.

        Args:
            proxy(CveRollbackTaskProxy): Cve rollback task proxy
            args(dict): request parameter.  e.g.
                {
                    "username": "admin",
                    "task_id": "string",
                    "host_id": "string",
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                    ],
                    "log": "",
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "fail",
                    "execution_time":""
                }

        Returns:
            int: status code
        """
        return CveRollbackCallback(proxy).callback(args)

    @BaseResponse.handle(schema=CveRollbackCallbackSchema, proxy=CveRollbackTaskProxy)
    def post(self, callback: CveRollbackTaskProxy, **params):
        """
        Args:
            callback(CveRollbackTaskProxy): Cve rollback task proxy
            params: e.g.
                {
                    "username": "admin",
                    "task_id": "string",
                    "host_id": "string",
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                    ],
                    "log": "",
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "fail",
                    "execution_time":""
                }

        Returns:
            dict: response body
        """
        return self.response(self._handle(callback, params))


class VulGenerateCveRollbackTask(BaseResponse):
    """
    Restful interface for generating a rollback task to rollback cve fix task.
    """

    def _handle(self, proxy: CveRollbackTaskProxy, args):
        """
        Handle rollback task generating

        Args:
            proxy (CveRollbackTaskProxy): database proxy
            args (dict): request parameter

        Returns:
            int: status code
            dict: body including task id
        """
        current_cluster_info = cache.location_cluster
        if not current_cluster_info:
            LOGGER.error("Failed to get current cluster id.")
            return DATABASE_QUERY_ERROR, {}, "Failed to get current cluster id."

        task_id = str(uuid.uuid1()).replace("-", "")
        task_info = dict(
            cluster_id=current_cluster_info.get("cluster_id"),
            task_id=task_id,
            fix_task_id=args["fix_task_id"],
            task_type=TaskType.CVE_ROLLBACK,
            create_time=int(time.time()),
            username=g.username,
        )

        # save task info to database
        status_code, msg = proxy.generate_cve_rollback_task(task_info)
        if status_code != SUCCEED:
            LOGGER.error("Generate cve rollback task fail.")
            return status_code, {}, msg
        return status_code, dict(task_id=task_id), msg

    @BaseResponse.handle(schema=GenerateCveRollbackTaskSchema, proxy=CveRollbackTaskProxy)
    def post(self, callback: CveRollbackTaskProxy, **params):
        """
        Args:
            callback (CveRollbackTaskProxy): database proxy
            params (dict): request parameter.  e.g.
                {"fix_task_id": "xxx"}

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "message": "",
                    "data": {"task_id": "1"}
                }
        """
        status_code, data, msg = self._handle(callback, params)
        return self.response(code=status_code, data=data, message=msg)


class VulGetCveRollbackTaskInfo(BaseResponse):
    """
    Restful interface for getting the host info of a cve rollback task.
    """

    @BaseResponse.handle(schema=GetCveRollbackTaskInfoSchema, proxy=CveRollbackTaskProxy)
    def post(self, callback: CveRollbackTaskProxy, **params):
        """
        Args:
            callback (CveRollbackTaskProxy): database proxy
            params (dict): request parameter.  e.g.
                {
                    "task_id": "xxx",
                    "page": 1,
                    "per_page": 10,
                    "filter": {"search_key": "host1/127.0.0.1", "status": ["succeed/fail/unknown/running"]}
                }

        Returns:
            dict: response body, e.g.
                {
                    "code": "200",
                    "label": "Succeed",
                    "message": "operation succeed",
                    "data": {
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
                }
        """
        status_code, data = callback.get_cve_rollback_task_host_info(params)
        return self.response(code=status_code, data=data)


class VulGetCveRollbackTaskRpmInfo(BaseResponse):
    """
    Restful interface for getting a host's rpm info of a cve rollback task.
    """

    @BaseResponse.handle(schema=GetCveRollbackTaskRpmInfoSchema, proxy=CveRollbackTaskProxy)
    def post(self, callback: CveRollbackTaskProxy, **params):
        """
        Args:
            callback (CveRollbackTaskProxy): database proxy
            params (dict): request parameter.  e.g.
                {
                    "task_id": "xxx",
                    "host_id": 1
                }

        Returns:
            dict: response body, e.g.
                {
                    "code": "200",
                    "label": "Succeed",
                    "message": "operation succeed",
                    "data": [
                        {
                            "installed_rpm": "pkg1-1",
                            "target_rpm": "pkg1",
                            "cves": "CVE-2023-3332,CVE-2023-23456",
                            "status": "succeed/fail/running/unknown"
                        }
                    ]
                }
        """
        status_code, data = callback.get_cve_rollback_host_rpm_info(params)
        return self.response(code=status_code, data=data)


class VulGetCveRollbackTaskResult(BaseResponse):
    """
    Restful interface for getting a CVE rollback task's result.
    """

    @BaseResponse.handle(schema=GetCveRollbackTaskResultSchema, proxy=CveRollbackTaskProxy)
    def post(self, callback: CveRollbackTaskProxy, **params):
        """
        Args:
            callback (CveRollbackTaskProxy): database proxy
            params (dict): request parameter.  e.g. {"task_id": "xxx"}

        Returns:
            dict: response body, e.g.
            {
                "code": "200",
                "data": [{
                    "host_id": 2,
                    "host_ip": "172.168.63.86",
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
                        "result": "succeed/failed",
                        "log": "string"
                    }
                }],
                "label": "Succeed",
                "message": "operation succeed"
            }
        """
        status_code, data = callback.get_cve_rollback_task_result(params)
        return self.response(code=status_code, data=data)


class VulGenerateHotpatchRemove(BaseResponse):
    """
    Restful interface for generating a cve hotpatch remove task.
    """

    def _handle(self, task_proxy: HotpatchRemoveProxy, params: dict):
        """
        Handle hotpatch remove task generating

        Args:
            task_proxy(MySqlProxy)
            params (dict): request parameter

        Returns:
            int: status code
            dict: body including task id
        """
        # query_host_info
        host_ids = [tmp["host_id"] for tmp in params.get("info", [])]
        query_fields = ["host_ip", "host_name", "host_id"]
        host_info_list = query_user_hosts(host_list=host_ids, fields=query_fields)

        if len(host_info_list) != len(host_ids):
            LOGGER.error("Failed to some host details info!")
            return PARAM_ERROR, {}

        # cve check
        cve_list = [cve["cve_id"] for host in params["info"] for cve in host["cves"]]
        if not task_proxy.check_cves_and_hotpatch_status(list(set(cve_list))):
            return PARAM_ERROR, {}

        current_cluster_info = cache.location_cluster
        if not current_cluster_info:
            LOGGER.error("Failed to get current cluster info!")
            return DATABASE_QUERY_ERROR, {}

        task_id = str(uuid.uuid1()).replace("-", "")
        task_info = dict(
            task_id=task_id,
            task_type=TaskType.HOTPATCH_REMOVE,
            create_time=int(time.time()),
            hosts=host_info_list,
            cluster_id=current_cluster_info.get("cluster_id"),
            username=g.username,
        )
        task_info.update(params)
        # save task info to database
        status_code = task_proxy.generate_hotpatch_remove_task(task_info)
        if status_code != SUCCEED:
            LOGGER.error("Generate hotpatch remove task fail.")
            return status_code, {}
        return status_code, dict(task_id=task_id)

    @BaseResponse.handle(schema=GenerateHotpatchRemoveTaskSchema, proxy=HotpatchRemoveProxy)
    def post(self, callback: HotpatchRemoveProxy, **params):
        """
        Args:
            task_name (str)
            description (str)
            info (list): task dict including host info and cves

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": "",
                    "data": {"task_id": "1"}
                }
        """
        status_code, data = self._handle(callback, params)
        return self.response(code=status_code, data=data)


class VulHotpatchRemoveTaskCallback(BaseResponse):
    """
    Restful interface for hotpatch remove task callback.
    """

    @BaseResponse.handle(schema=HotpatchRemoveCallbackSchema, proxy=HotpatchRemoveProxy)
    def post(self, callback: HotpatchRemoveProxy, **params):
        """
        Args:
            host_id (str)
            task_id (str)
            cves (list) e.g
                [{
                    "cve_id":"cveid1",
                    "result":"",
                    "log":""
                }]

        Returns:
            dict: response body
        """
        status_code = HotpatchRemoveCallback(callback).callback(params)
        return self.response(code=status_code)


class VulGetTaskCveRpmInfo(BaseResponse):
    """
    Restful interface for query cve's rpm info about cve-fix task
    """

    @BaseResponse.handle(schema=TaskCveRpmInfoSchema, proxy=CveFixTaskProxy)
    def post(self, callback: CveFixTaskProxy, **params):
        """
        Args:
            task_id (str)
            host_id (int)

        Returns:
            dict: response body
        """

        status_code, data = callback.query_task_cve_fix_rpm_info(params["task_id"], params["host_id"])
        return self.response(code=status_code, data=data)


class VulCveScanNotice(BaseResponse):
    @BaseResponse.handle(proxy=HostProxy)
    def post(self, callback: HostProxy, **params):
        """
        Restful interface for email notifications
        """
        manager = EmailNoticeManager(g.username, callback)
        manager.send_email_to_user()
        return self.response(code=SUCCEED)


class VulGetHotpatchRemoveTaskCveInfo(BaseResponse):
    """
    Restful interface for getting the info of a task which hotpatch remove.
    """

    @BaseResponse.handle(schema=GetHotpatchRemoveTaskCveInfoSchema, proxy=HotpatchRemoveProxy)
    def post(self, callback: HotpatchRemoveProxy, **params):
        """
        Args:
            task_id (str)
            sort (str, optional): can be chosen from host_num.
            direction (str, optional): asc or desc. Defaults to asc.
            page (int, optional): current page in web.
            per_page (int, optional): number of items in each page.
            filter (dict, optional): filter condition.

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": "",
                    "result": [
                        {
                            "cve_id": "cve-11-1",
                            "package": "",
                            ""
                        }
                    ]
                }

        """
        status_code, data = callback.get_hotpatch_remove_task_cve_info(params)
        return self.response(code=status_code, data=data)


class VulGetHotpatchRemoveTaskResult(BaseResponse):
    """
    Restful interface for getting a hotpatch remove task's result.
    """

    @BaseResponse.handle(schema=GetTaskResultSchema, proxy=HotpatchRemoveProxy)
    def post(self, callback: HotpatchRemoveProxy, **params):
        """
        Args:
            task_id (str): task id

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": "",
                    "result": {
                        "task_id": "1",
                        "task_type": "cve",
                        "latest_execute_time": 11,
                        "task_result": [
                            {
                                "host_id": 1,
                                "host_name": "name",
                                "host_ip": "1.1.1.1",
                                "status": "fail",
                                "check_items": [
                                    {
                                        "item": "check network",
                                        "result": True
                                    }
                                ],
                                "cves": [
                                    {
                                        "cve_id": "cve-11-1",
                                        "log": "",
                                        "result": "unfixed"
                                    }
                                ]
                            }
                        ]
                    }
                }

        """
        status_code, data = callback.get_hotpatch_remove_task_result(params)
        return self.response(code=status_code, data=data)


class VulGetHotpatchRemoveTaskProgress(BaseResponse):
    """
    Restful interface for getting progress of the task which hotpatch remove.
    """

    @BaseResponse.handle(schema=GetHotpatchRemoveTaskProgressSchema, proxy=HotpatchRemoveProxy)
    def post(self, callback: HotpatchRemoveProxy, **params):
        """
        Args:
            task_id (str): task id
            cve_list (list): cve id list

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": "",
                    "result": {
                        "cve1": {
                            "progress": 1,
                            "status": "running"
                        },
                        "cve2": {
                            "progress": 2,
                            "status": "succeed
                        }
                    }
                }
        """
        status_code, data = callback.get_hotpatch_remove_task_cve_progress(params)
        return self.response(code=status_code, data=data)


class VulGetTaskHost(BaseResponse):
    """
    Restful interface for getting hosts of the task.
    """

    @BaseResponse.handle(schema=GetTaskResultSchema, proxy=TaskProxy)
    def post(self, callback: TaskProxy, **params):
        """
        Args:
            callback(TaskProxy): task proxy
            params(dict): e.g. {"task_id": "xxx"}

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": "",
                    "data": [1,2,3]
                }
        """
        status_code, data = callback.get_task_hosts(params["task_id"])
        return self.response(code=status_code, data=data)


class VulGenerateCveFixAndExecute(VulGenerateCveFixTask):

    def _handle_fix_task(self, execute_queue: list):

        args = (execute_queue, request.headers.get("access-token"))
        try:
            group(celery_client.signature(TaskChannel.CVE_FIX_AND_EXECUTE_TASK, args=args)).apply_async()
            return SUCCEED
        except CeleryError as error:
            LOGGER.error(error)
            LOGGER.error("Failed to execute CVE fix task with ID: %s", self.task_id)
            return TASK_EXECUTION_FAIL

    @BaseResponse.handle(schema=GenerateCveTaskSchema, proxy=CveFixTaskProxy)
    def post(self, callback: TaskProxy, **params):
        """
        Args:
            callback(TaskProxy): task proxy
            params(dict): e.g. {"cve_id": "xxx", "host_id": "xxx"}

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "data": {
                        "task_id": "xxx"
                    }
                }
        """
        # e.g.
        # data = [
        #        {
        #             "task_id": "8878b35288df11eeb0815254001a9e0d",
        #             "fix_way": "hotpatch/coldpatch"
        #        }
        #      ]
        status_code, data = self._handle(params, callback)
        if status_code != SUCCEED:
            return self.response(code=status_code)
        # start execute task
        execute_queue = []
        for task in data:
            if task["fix_way"] == "hotpatch":
                execute_queue.insert(0, task["task_id"])
            elif task["fix_way"] == "coldpatch":
                execute_queue.append(task["task_id"])
        status_code = self._handle_fix_task(execute_queue)
        return self.response(code=status_code, data=data)


class VulTaskExecuteStatus(BaseResponse):
    """
    Restful api for get task execute status
    """

    @BaseResponse.handle(schema=ExecuteTaskSchema, proxy=TaskProxy)
    def get(self, callback: TaskProxy, **params):
        """
        Args:
            callback(TaskProxy): task proxy
            params(dict): e.g. {"task_id": "xxx"}

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": "",
                    "data": true/false
                }
        """
        cluster_info = cache.get_user_clusters()
        if not cluster_info:
            return self.response(code=PERMESSION_ERROR)

        task_type = callback.get_task_type(params["task_id"], cluster_info.keys())
        running = callback.check_task_status(params["task_id"], task_type)
        return self.response(code=SUCCEED, data=running)
