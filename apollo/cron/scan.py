#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2023. All rights reserved.
# licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN 'AS IS' BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/
import datetime
import uuid
from urllib.parse import urlencode

from redis.exceptions import RedisError
from vulcanus.conf.constant import ADMIN_USER, HOSTS_FILTER
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import SUCCEED
from vulcanus.restful.response import BaseResponse
from vulcanus.rsa import load_private_key, sign_data

from apollo.conf import cache, configuration
from apollo.handler.task_handler.manager.scan_manager import ScanManager


class TimedScanTask:
    """
    Timed scanning tasks
    """

    def query_scanning_host(self):
        """
        Query all hosts that are in scanning status
        """
        try:
            scanning_host_list = cache.hash(cache.SCANNING_HOST_KEY)
            if scanning_host_list:
                return scanning_host_list.keys()
        except RedisError:
            LOGGER.warning("Failed to query scanning host info!")
        return []

    def query_all_host_info(self, scanning_hosts_ids):
        """
        Get all host information that needs to be scanned
        """

        local_cluster_info = cache.location_cluster
        request_args = {
            "cluster_list": [local_cluster_info.get("cluster_id")],
            "fields": ["host_id", "host_ip", "host_name", "status", "ssh_user", "ssh_port", "pkey"],
        }
        signature = sign_data(request_args, load_private_key(local_cluster_info.get("private_key")))
        headers = {"X-Permission": "RSA", "X-Signature": signature, "X-Cluster-Username": ADMIN_USER}

        url = f"http://{configuration.domain}{HOSTS_FILTER}?{urlencode(request_args)}"
        response_data = BaseResponse.get_response(method="GET", url=url, data={}, header=headers)
        if response_data.get("label") != SUCCEED:
            LOGGER.warning(f"Failed to query host information during timed scanning task.")

        return [host for host in response_data.get("data", []) if host.get("host_id") not in scanning_hosts_ids]

    def execute(self):
        """
        Start the scan after the specified time of day.
        """
        LOGGER.info("Begin to scan the whole host in %s.", str(datetime.datetime.now()))
        # Get all host info
        current_cluster_info = cache.location_cluster
        if not current_cluster_info:
            LOGGER.error("Failed to get the current cluster id, stop timed scanning task.")
            return

        host_info_list = self.query_all_host_info(self.query_scanning_host())
        if not host_info_list:
            return

        task_id = str(uuid.uuid1()).replace('-', '')
        cve_scan_manager = ScanManager(task_id, None, host_info_list, current_cluster_info.get("cluster_id"))
        # create works
        cve_scan_manager.create_task()
        if not cve_scan_manager.pre_handle():
            return
        # run the tas in a thread
        cve_scan_manager.execute_task()
