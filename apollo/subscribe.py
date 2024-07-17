#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
# licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN 'AS IS' BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/
import json
import time
from typing import List

from apollo.conf.constant import TaskChannel
from apollo.cron import CorrectTask, DownloadSATask, NotificationTask, TimedScanTask
from apollo.database.proxy.task.cve_fix import CveFixTaskProxy
from apollo.database.proxy.task.cve_rollback import CveRollbackTaskProxy
from apollo.database.proxy.task.hotpatch_remove import HotpatchRemoveProxy
from apollo.database.proxy.task.repo_set import RepoSetProxy
from apollo.database.proxy.task.scan import ScanProxy
from apollo.database.proxy.task.synchronize_cancel import SynchronizeCancelProxy
from apollo.handler.task_handler.callback.cluster_synchronize_cancel import SynchronizeCancelCallback
from apollo.handler.task_handler.callback.cve_fix import CveFixCallback
from apollo.handler.task_handler.callback.cve_rollback import CveRollbackCallback
from apollo.handler.task_handler.callback.cve_scan import CveScanCallback
from apollo.handler.task_handler.callback.hotpatch_remove import HotpatchRemoveCallback
from apollo.handler.task_handler.callback.repo_set import RepoSetCallback
from redis import Redis, RedisError
from vulcanus.exceptions.database_exception import DatabaseConnectionFailed
from vulcanus.log.log import LOGGER


class TaskCallbackSubscribe:
    """
    Handles callback logic for different task channels.
    """

    CHANNEL = {
        TaskChannel.CVE_SCAN_TASK: (CveScanCallback, ScanProxy),
        TaskChannel.CVE_FIX_TASK: (CveFixCallback, CveFixTaskProxy),
        TaskChannel.REPO_SET_TASK: (RepoSetCallback, RepoSetProxy),
        TaskChannel.CVE_ROLLBACK_TASK: (CveRollbackCallback, CveRollbackTaskProxy),
        TaskChannel.HOTPATCH_REMOVE_TASK: (HotpatchRemoveCallback, HotpatchRemoveProxy),
        TaskChannel.CLUSTER_SYNCHRONIZE_CANCEL_TASK: (SynchronizeCancelCallback, SynchronizeCancelProxy),
    }

    def __init__(self, subscribe_client: Redis, channels: List[str]) -> None:
        self._subscribe = subscribe_client
        self._channels = channels
        self.subscribe_message = None

    def __call__(self, *args, **kwargs):
        """
        Subscribe to Redis channels and execute a callback function for each received message.
        """
        while True:
            try:
                subscribe = self._subscribe.pubsub()
                for channel in self._channels:
                    subscribe.subscribe(channel)

                for message in subscribe.listen():
                    if message["type"] != "message":
                        continue
                    if message["channel"] not in TaskCallbackSubscribe.CHANNEL:
                        self._timed_task(message["channel"], json.loads(message["data"]))
                    else:
                        self.handle_callback(message["channel"], json.loads(message["data"]))
            except RedisError as error:
                LOGGER.error(f"Failed to subscribe to channels {self._channels}: {error}")
                time.sleep(1)
            except Exception as error:
                LOGGER.error(error)
                time.sleep(1)

    def _timed_task(self, channel, task_execute_result: dict) -> None:
        lock = f"{channel}-timed"
        if not self._subscribe.set(lock, 'locked', nx=True, ex=30):
            LOGGER.warning("Another timed task is running, skip this subscribe.")
            return

        channel_fun = getattr(self, channel, None)
        if channel_fun and callable(channel_fun):
            channel_fun(task_execute_result)
            return

        LOGGER.warning(f"Unsupported task type: {channel}")

    def cve_scan(self, message: dict) -> None:
        """
        Callback function for CVE scan task.

        Args:
            message (dict): The message received from the Redis channel.
        """
        LOGGER.info(f"Received CVE scan task: {message}")
        cve_scan_task = TimedScanTask()
        cve_scan_task.execute()

    def download_sa(self, message: dict):
        """
        Callback function for download SA task.

        Args:
            message (dict): The message received from the Redis channel.
        """
        LOGGER.info(f"Received download SA task: {message}")
        download_sa_task = DownloadSATask(cvrf=message.get("cvrf", None))
        download_sa_task.execute()

    def correct_data(self, message: dict) -> None:
        """
        Callback function for correct data task.

        Args:
            message (dict): The message received from the Redis channel.
        """
        LOGGER.info(f"Received correct data task: {message}")
        correct_data_task = CorrectTask()
        correct_data_task.execute()

    def send_notification(self, message: dict) -> None:
        """
        Callback function for sending notification task.

        Args:
            message (dict): The message received from the Redis channel.
        """
        LOGGER.info(f"Received send notification task: {message}")
        NotificationTask().execute()

    def handle_callback(self, channel: str, task_execute_result: dict) -> None:
        """
        Handles callback based on the task channel and task execution result.

        Args:
            channel (str): The name of the task channel.
            task_execute_result (dict): The result of the task execution.
        """
        if channel == TaskChannel.CLUSTER_SYNCHRONIZE_CANCEL_TASK:
            lock = f"cluster_synchronize_cancel_task_apollo_subscribe-{task_execute_result['cluster_id']}"
        else:
            lock = f"{channel}-{task_execute_result.get('task_id')}-{task_execute_result.get('host_id')}"
        if not self._subscribe.set(lock, 'locked', nx=True, ex=30):
            LOGGER.warning("Another callback task is running, skip this subscribe.")
            return

        try:
            callback_cls, proxy_cls = TaskCallbackSubscribe.CHANNEL.get(channel)
            with proxy_cls() as proxy:
                callback_cls(proxy).callback(task_execute_result)
        except ValueError:
            LOGGER.error("Unsupported task type")
        except DatabaseConnectionFailed:
            LOGGER.error(
                f"Failed to handle the result of task {channel} (ID: {task_execute_result.get('task_id')})"
                f"{task_execute_result.get('host_id')}."
            )
