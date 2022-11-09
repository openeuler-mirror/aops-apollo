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
import json
import os
import threading
import time
import uuid
from typing import Dict, Tuple

import yaml
from flask import jsonify, request

from apollo.conf.constant import CVE_SCAN_STATUS
from apollo.database import SESSION
from apollo.database.proxy.task import TaskMysqlProxy, TaskProxy
from apollo.function.schema.host import ScanHostSchema
from apollo.function.schema.task import *
from apollo.function.utils import make_download_response
from apollo.handler.task_handler.callback.cve_fix import CveFixCallback
from apollo.handler.task_handler.callback.repo_set import RepoSetCallback
from apollo.handler.task_handler.config import \
    cve_fix_func, PLAYBOOK_DIR, INVENTORY_DIR, configuration, \
    CVE_CHECK_ITEMS, REPO_CHECK_ITEMS
from apollo.handler.task_handler.manager.cve_fix_manager import CveFixManager
from apollo.handler.task_handler.manager.playbook_manager import \
    CveFixPlaybook, RepoPlaybook
from apollo.handler.task_handler.manager.repo_manager import RepoManager
from apollo.handler.task_handler.manager.scan_manager import ScanManager
from vulcanus.log.log import LOGGER
from vulcanus.restful.response import BaseResponse
from vulcanus.restful.status import \
    DATABASE_CONNECT_ERROR, REPEAT_TASK_EXECUTION, SUCCEED, PARAM_ERROR, \
    DATABASE_UPDATE_ERROR


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
            if host['status'] == CVE_SCAN_STATUS.SCANNING:
                return False
            host_list.append(host['host_id'])

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

    def _handle(self, args):
        """
        Generate scan task according to host info, and run it.

        Args:
            args (dict): request parameter

        Returns:
            int: status code
        """
        # connect to database
        proxy = TaskMysqlProxy()
        if not proxy.connect(SESSION):
            LOGGER.error("Connect to database fail, return.")
            return DATABASE_CONNECT_ERROR

        # verify host id
        username = args['username']
        host_list = args['host_list']
        host_info = proxy.get_scan_host_info(username, host_list)
        if not self._verify_param(host_list, host_info):
            proxy.close()
            LOGGER.error(
                "There are some host in %s that can not be scanned.", host_list)
            return PARAM_ERROR

        # generate playbook and inventory of the scanning task
        task_id = ScanManager.generate_playbook_and_inventory(host_info)
        LOGGER.debug(task_id)

        # init status
        manager = ScanManager(task_id, proxy, host_info, username)
        if not manager.pre_handle():
            return DATABASE_UPDATE_ERROR

        # run the task in a thread
        task_thread = threading.Thread(target=manager.execute_task)
        task_thread.start()

        return SUCCEED

    def post(self):
        """
        Scan host's cve

        Args:
            host_list (list): host id list

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request(ScanHostSchema, self))


class VulGetTaskList(BaseResponse):
    """
    Restful interface for getting task(cve fixing or repo setting) list.
    """

    def post(self):
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
        return jsonify(self.handle_request_db(GetTaskListSchema,
                                              TaskMysqlProxy(),
                                              "get_task_list",
                                              SESSION))


class VulGetTaskProgress(BaseResponse):
    """
    Restful interface for getting task progress.
    """

    def post(self):
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
                            "on standby": 0
                        }
                    }
                }
        """
        return jsonify(self.handle_request_db(GetTaskProgressSchema,
                                              TaskMysqlProxy(),
                                              "get_task_progress",
                                              SESSION))


class VulGetTaskInfo(BaseResponse):
    """
    Restful interface for getting basic info of a task.
    """

    def get(self):
        """
        Args:
            task_id (str): task id

        Returns:
            dict: response body, e,g,
                {
                    "code": 200,
                    "msg": "",
                    "result": {
                        "task_name": "task",
                        "description": "",
                        "host_num": 15,
                        "need_reboot": 2,
                        "auto_reboot": True,
                        "latest_execute_time": 11
                    }
                }
        """
        return jsonify(self.handle_request_db(GetTaskInfoSchema,
                                              TaskMysqlProxy(),
                                              "get_task_info",
                                              SESSION))


class VulGenerateCveTask(BaseResponse):
    """
    Restful interface for generating a cve task.
    """
    @staticmethod
    def _handle(args):
        """
        Handle cve generating task.

        Args:
            args (dict): request param

        Returns:
            int: status code
            dict: body including task id
        """
        result = {"task_id": ""}
        # save task info to database
        task_proxy = TaskProxy(configuration)
        if not task_proxy.connect(SESSION):
            LOGGER.error("Connect to database fail, return.")
            return DATABASE_CONNECT_ERROR, result

        task_id = str(uuid.uuid1()).replace('-', '')
        args['task_id'] = task_id
        args['task_type'] = 'cve'
        args['create_time'] = int(time.time())
        status_code, basic_info = task_proxy.generate_cve_task(args)
        if status_code != SUCCEED:
            LOGGER.error(
                "Generate cve fix task fail, fail to save task info to database.")
            return status_code, result

        status_code, package_info = task_proxy.get_package_info(basic_info)
        if status_code != SUCCEED:
            LOGGER.error(
                "Generate cve fix task fail, there is no package info about cve.")
            return status_code, result

        time.sleep(1)
        # generate playbook and hosts, dump to file and save to es database.
        pb_manager = CveFixPlaybook(
            task_id, True, CVE_CHECK_ITEMS, cve_fix_func)
        inventory = pb_manager.create_fix_inventory(basic_info)
        playbook = pb_manager.create_fix_playbook(basic_info, package_info)
        task_proxy.save_task_info(task_id, json.dumps(
            playbook), json.dumps(inventory))
        result['task_id'] = task_id

        return SUCCEED, result

    def post(self):
        """
        Args:
            task_name (str)
            description (str)
            auto_reboot (bool, optional): when auto_reboot is set and reboot is true,
                                the host will be rebooted after fixing cve
            info (list): task info including cve id and related host info

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": "",
                    "task_id": "id1"
                }
        """
        return jsonify(self.handle_request(GenerateCveTaskSchema, self))


class VulGetCveTaskInfo(BaseResponse):
    """
    Restful interface for getting the info of a task which fixes cve.
    """

    def post(self):
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
        return jsonify(self.handle_request_db(GetCveTaskInfoSchema,
                                              TaskMysqlProxy(),
                                              "get_cve_task_info",
                                              SESSION))


class VulGetCveTaskStatus(BaseResponse):
    """
    Restful interface for getting host status in the task which fixes cve.
    """

    def post(self):
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
                                "host_id": "id1",
                                "host_name": "name1",
                                "host_ip": "ip1",
                                "status": "running"
                            }
                        ]
                    }
                }
        """
        return jsonify(self.handle_request_db(GetCveTaskStatusSchema,
                                              TaskMysqlProxy(),
                                              "get_task_cve_status",
                                              SESSION))


class VulGetCveTaskProgress(BaseResponse):
    """
    Restful interface for getting progress of the task which fixes cve.
    """

    def post(self):
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
        return jsonify(self.handle_request_db(GetCveTaskProgressSchema,
                                              TaskMysqlProxy(),
                                              "get_task_cve_progress",
                                              SESSION))


class VulGetCveTaskResult(BaseResponse):
    """
    Restful interface for getting a CVE task's result.
    """

    def post(self):
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
                                "host_id": "1",
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
        return jsonify(self.handle_request_db(GetCveTaskResultSchema,
                                              TaskProxy(configuration),
                                              "get_task_cve_result",
                                              SESSION))


class VulRollbackCveTask(BaseResponse):
    """
    Restful interface for rollback a cve task.
    """

    def _handle(self, args):
        """
        Handle rollback task.

        Args:
            args (dict): request param

        Returns:
            int: status code
        """

        return SUCCEED

    def post(self):
        """
        Args:
            task_id (str): task id
            cve_list (list): cve id list

        Returns:
            dict: response body, e.g.
                {
                    "code": 200,
                    "msg": ""
                }

        """
        return jsonify(self.handle_request(RollbackCveTaskSchema, self))


class VulGenerateRepoTask(BaseResponse):
    """
    Restful interface for generating a task which sets repo for host.
    """
    @staticmethod
    def _handle(args):
        """
        Handle repo task generating

        Args:
            args (dict): request parameter

        Returns:
            int: status code
            dict: body including task id
        """
        task_id = str(uuid.uuid1()).replace('-', '')
        task_info = dict(task_id=task_id, task_type="repo set",
                         create_time=int(time.time()), username=args["username"])
        task_info.update(args)

        # connect to database
        task_proxy = TaskProxy(configuration)
        if not task_proxy.connect(SESSION):
            return DATABASE_CONNECT_ERROR, task_info

        # save task info to database
        status_code = task_proxy.generate_repo_task(task_info)
        if status_code != SUCCEED:
            LOGGER.error("Generate repo setting task fail.")

        return status_code, dict(task_id=task_id)

    def post(self):
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
                    "task_id": "1"
                }
        """
        return jsonify(self.handle_request(GenerateRepoTaskSchema, self))


class VulGetRepoTaskInfo(BaseResponse):
    """
    Restful interface for getting the info of a task which sets repo.
    """

    def post(self):
        """
        Args:
            task_id (str)
            page (int, optional): current page in web
            per_page (int, optional): host number of each page
            filter (dict, optional): filter condition

        Returns:
            dict: response body
        """
        return jsonify(self.handle_request_db(GetRepoTaskInfoSchema,
                                              TaskMysqlProxy(),
                                              "get_repo_task_info",
                                              SESSION))


class VulGetRepoTaskResult(BaseResponse):
    """
    Restful interface for getting the result of a task which sets repo.
    """

    def post(self):
        """
        Args:
            task_id (str)
            host_list (list): host id list

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request_db(GetRepoTaskResultSchema,
                                              TaskProxy(configuration),
                                              "get_task_repo_result",
                                              SESSION))


class VulExecuteTask(BaseResponse):
    """
    Restful interface for executing task.
    """
    type_map = {
        "cve": "_handle_cve",
        "repo set": "_handle_repo"
    }

    @staticmethod
    def _handle_cve(args, proxy):
        """
        Handle cve task

        Args:
            args (dict)
            proxy (object)

        Returns:
            int: status code
        """
        task_id = args['task_id']
        # check host info
        task_info = TASK_CACHE.get(task_id)
        if task_info is None:
            status_code, info = proxy.get_cve_basic_info(task_id)
            if status_code == SUCCEED:
                task_info = TASK_CACHE.make_cve_info(info)
                TASK_CACHE.put(task_id, task_info)
            else:
                LOGGER.error(
                    "There is no data about host info, stop cve fixing.")
                return NO_DATA

        # check playbook and inventory
        if not Playbook.check_pb_and_inventory(task_id, proxy):
            LOGGER.error(
                "Check playbook and inventory failed before running task %s.", task_id)
            return NO_DATA

        manager = CveFixManager(proxy, task_id, task_info)
        if not manager.pre_handle():
            return DATABASE_UPDATE_ERROR

        # run the task in a thread
        task_thread = threading.Thread(target=manager.execute_task)
        task_thread.start()

        return SUCCEED

    @staticmethod
    def _handle_repo(args, proxy):
        """
        Handle repo task

        Args:
            args (dict)
            proxy (object)

        Returns:
            int: status code
        """
        repo_manager = RepoManager(proxy, args['task_id'])

        repo_manager.token = args['token']
        status_code = repo_manager.create_task(args['username'])
        if status_code != SUCCEED:
            return status_code

        if not repo_manager.pre_handle():
            return DATABASE_UPDATE_ERROR

        # After several check, run the task in a thread
        task_thread = threading.Thread(target=repo_manager.execute_task)
        task_thread.start()

        return SUCCEED

    def _handle(self, args):
        """
        Handle executing task, now support cve and repo.

        Args:
            args (dict): request parameter

        Returns:
            int: status code
        """
        access_token = request.headers.get('access_token')
        args['token'] = access_token

        proxy = TaskProxy(configuration)
        if not proxy.connect(SESSION):
            return DATABASE_CONNECT_ERROR
        # verify the task:
        # 1.belongs to the user;
        # 2.task type is supported.
        task_type = proxy.get_task_type(args['task_id'], args['username'])
        if task_type is None or task_type not in self.type_map.keys():
            return PARAM_ERROR
        LOGGER.debug(task_type)

        if not proxy.check_task_status(args['task_id'], task_type):
            return REPEAT_TASK_EXECUTION

        func_name = self.type_map[task_type]
        func = getattr(self, func_name)

        return func(args, proxy)

    def post(self):
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
        return jsonify(self.handle_request(ExecuteTaskSchema, self))


class VulDeleteTask(BaseResponse):
    """
    Restful interface for deleting tasks.
    """
    @staticmethod
    def _delete_task_file(task_list):
        """
        When the task is deleted, the related local files, e.g. plabook and inventory
        need to be deleted too.

        Args:
            task_list (list): task id list
        """
        for task_id in task_list:
            need_deleted_path = [os.path.join(INVENTORY_DIR, task_id),
                                 os.path.join(PLAYBOOK_DIR, task_id + '.yml')]
            for path in need_deleted_path:
                if os.path.exists(path):
                    os.remove(path)

    def _handle(self, args):
        """
        Handle executing task, now support cve and repo.

        Args:
            args (dict): request parameter

        Returns:
            int: status code
        """
        proxy = TaskProxy(configuration)
        if not proxy.connect(SESSION):
            return DATABASE_CONNECT_ERROR

        status_code = proxy.delete_task(args)
        if status_code == SUCCEED:
            self._delete_task_file(args['task_list'])

        return status_code

    def delete(self):
        """
        Args:
            task_list (list): task id list

        Returns:
            dict: response body
        """
        return jsonify(self.handle_request(DeleteTaskSchema, self))


class VulGetTaskPlaybook(BaseResponse):
    """
    Restful interface for getting the playbook of a task.
    """
    type_map = {
        "cve": "_handle_cve",
        "repo": "_handle_repo"
    }
    proxy = None
    file_name = ""
    file_path = ""

    def _handle_cve(self, task_id):
        """
        Handle playbook downloading of cve fixing task.

        Args:
            task_id (str)

        Returns:
            int: status code
        """
        status_code, basic_info = self.proxy.get_cve_basic_info(task_id)
        if status_code != SUCCEED:
            return status_code

        status_code, package_info = self.proxy.get_package_info(basic_info)
        if status_code != SUCCEED:
            return status_code

        pb_manager = CveFixPlaybook(
            task_id, True, CVE_CHECK_ITEMS, cve_fix_func)
        playbook = pb_manager.create_fix_playbook(basic_info, package_info)
        self.proxy.save_task_info(task_id, json.dumps(playbook))

        return SUCCEED

    @staticmethod
    def _handle_repo(task_id):
        """
        Handle playbook downloading of repo setting task.

        Args:
            proxy (object): database proxy instance
            task_id (str)

        Returns:
            int: status code
        """
        pb_manager = RepoPlaybook(task_id, True, REPO_CHECK_ITEMS)
        pb_manager.create_playbook()
        return SUCCEED

    def _handle(self, args):
        """
        Handle playbook download.

        Args:
            args (dict): request parameter

        Returns:
            int: status code
        """
        task_id = args['task_id']

        self.proxy = TaskProxy(configuration)
        if not self.proxy.connect(SESSION):
            return DATABASE_CONNECT_ERROR

        # verify the task:
        # 1.belongs to the user;
        # 2.task type is supported.
        task_type = self.proxy.get_task_type(task_id, args['username'])
        if task_type is None or task_type != args['task_type']:
            LOGGER.error("The task id %s and task type %s is not matched, return.",
                         task_id, args['task_type'])
            return PARAM_ERROR

        self.file_name = "{}.{}".format(task_id, "yml")
        self.file_path = os.path.join(PLAYBOOK_DIR, self.file_name)
        # when the playbook file is not existed in local
        if not os.path.exists(self.file_path):
            LOGGER.info(
                "the queried playbook doesn't exist in local, try to query from database")
            status_code, playbook = self.proxy.get_task_ansible_info(
                task_id, 'playbook')
            if status_code == SUCCEED and playbook:
                playbook = json.loads(playbook)
                with open(self.file_path, 'w', encoding='utf-8') as stream:
                    yaml.dump(playbook, stream)
            else:
                LOGGER.info(
                    "the queried playbook doesn't exist in database, try to regenerate it")
                func_name = self.type_map[args['task_type']]
                func = getattr(self, func_name)
                status, _ = func(task_id)
                if status != SUCCEED:
                    return status

        return SUCCEED

    def get(self):
        """
        Args:
            task_id (str): task id
            task_type (str): task type (cve/repo)

        Returns:
            dict: response body
        """
        response = self.handle_request(GetTaskPlaybookSchema, self)
        if response['code'] == SUCCEED:
            return make_download_response(self.file_path, self.file_name)

        return jsonify(response)


class VulRepoSetTaskCallback(BaseResponse):
    """
    Restful interface for set repo callback.
    """
    @staticmethod
    def _handle(args):
        """
        Handle set repo callback.

        Args:
            args (dict): request parameter

        Returns:
            int: status code
        """
        proxy = TaskProxy(configuration)
        if not proxy.connect(SESSION):
            return DATABASE_CONNECT_ERROR
        task_info = dict(
            status=args["status"], repo_name=args["repo_name"], host_id=args["host_id"])

        repo_set_callback = RepoSetCallback(proxy)
        return repo_set_callback.callback(args['task_id'], task_info)

    def post(self):
        """
        Args:
            host_id (str)
            status (str)
            task_id (str)
            repo_name (str)

        Returns:
            dict: response body
        """
        return jsonify(self.handle_request(RepoSetCallbackSchema, self))


class VulCveFixTaskCallback(BaseResponse):
    """
    Restful interface for cve fix callback.
    """
    @staticmethod
    def _handle(args):
        """
        Handle cve fix callback.

        Args:
            args (dict): request parameter

        Returns:
            int: status code
        """
        proxy = TaskProxy(configuration)
        if not proxy.connect(SESSION):
            return DATABASE_CONNECT_ERROR

        return CveFixCallback(proxy).callback(
            args['task_id'], args['host_id'], args['cves'])

    def post(self):
        """
        Args:
            task_id (str)
            host_id (str)
            cves (dict)

        Returns:
            dict: response body
        """
        return jsonify(self.handle_request(CveFixCallbackSchema, self))
