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
Description: Task manager for notification
"""
import os
import tempfile
import time
from collections import defaultdict
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Tuple
from urllib.parse import urlencode

from vulcanus.conf.constant import ADMIN_USER, HOSTS_FILTER, PERMISSIONS, USERS_ALL
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp import state
from vulcanus.restful.response import BaseResponse
from vulcanus.rsa import load_private_key, sign_data
from vulcanus.send_email import Email

from apollo.conf import cache, configuration
from apollo.database.proxy.host import HostProxy


class EmailNoticeManager:
    """
    email notice method manager
    """

    def __init__(
        self,
        username: str,
        proxy: HostProxy,
        host_info_list: List[Dict[str, str]],
        receiver: str = None,
    ) -> None:
        self.username = username
        self.proxy = proxy
        self.receiver = receiver
        self.host_info_list = host_info_list

    def send_email_to_user(self) -> None:
        """
        send email to user with cve scan result
        """
        # Get config info
        server = configuration.email.server
        port = configuration.email.port
        authorization_code = configuration.email.authorization_code
        sender = configuration.email.sender
        # Generate email body
        status_code, tempfile_path, table_data = self._generate_cve_info_file()
        if status_code != state.SUCCEED:
            LOGGER.error(f'Generate cve info file failed, status_code: {status_code}')
            return

        message = self._generate_email_body(sender, self.receiver, table_data, tempfile_path)
        # send email
        email_obj = Email(server, port, sender, authorization_code)
        email_obj.send(self.receiver, message)

    def _generate_email_body(
        self, sender: str, receivers: str, table_data: list, file_path: str = None
    ) -> MIMEMultipart:
        """
        The function used to generate email content

        Args:
            sender: Email Sender
            receivers: The recipient of the email

        Return:
            MIMEMultipart: Mail Object
        """
        message = MIMEMultipart('mixed')
        # set email subject
        message['Subject'] = f'{time.strftime("【%Y-%m-%d", time.localtime())} A-OPS】CVE扫描结果'
        message['From'] = f'A-OPS<{sender}>'
        message['To'] = receivers

        # set email text content
        body_head = "<p>下表为各主机CVE信息简略统计表：</p>"
        host_list_url = f'http://{configuration.domain}/vulnerability/hosts/hosts-list'
        body_tail = f'<p>详细CVE信息请查看附件</p><a href="{host_list_url}">点击跳转AOPS</a>'
        table_title = ["主机名", "主机IP", "CVE个数"]
        html = f"{body_head}{Email.turn_data_to_table_html(table_title, table_data)}{body_tail}"
        text_content = MIMEText(html, "html", "utf-8")
        message.attach(text_content)

        # Attach file if file_path is provided
        if file_path and os.path.isfile(file_path):
            with open(file_path, 'rb') as file:
                file_content = MIMEApplication(file.read())
                file_content.add_header('Content-Disposition', 'attachment', filename=f"主机CVE信息统计表.csv")
                message.attach(file_content)

        return message

    def generate_temp_file(self) -> Tuple[str, str, list]:
        """
        Generate a temporary file containing host information and CVE details.

        Returns:
            Tuple[str, str, list]: A tuple containing the path of the generated temporary file,
            the status (SUCCEED or DATABASE_QUERY_ERROR), file path and a chart data (host_name, host_ip, cve_count).
        """
        cluster_info = cache.clusters
        chart_data = []
        with tempfile.NamedTemporaryFile(delete=False, mode="w", newline='', encoding='utf-8') as temp_file:
            temp_file_path = temp_file.name
            chart_head = "Host,Host Name,Cluster Name,CVE ID,CVSS Score,Severity,Source Rpm Name,Installed Rpm Name,Upgradable Package Name,Fixed Way\n"
            temp_file.write(chart_head)

            for host in self.host_info_list:
                cve_set = set()
                content = ""
                status, cve_info_list = self.proxy.query_host_cve_info(host.get("host_id"))
                if status != state.SUCCEED:
                    return state.DATABASE_QUERY_ERROR, temp_file_path, chart_data
                for cve_info in cve_info_list:
                    content += (
                        f'{host.get("host_ip")},{host.get("host_name")},'
                        f'{cluster_info.get(host.get("cluster_id"), {}).get("cluster_name")},{cve_info["cve_id"]},{cve_info["cvss_score"]},'
                        f'{cve_info["severity"]},{";".join(cve_info["source_package"])},{cve_info["installed_rpm"]},'
                        f'{";".join(cve_info["available_rpms"])},{";".join(cve_info["support_ways"])},\n'
                    )
                    cve_set.add(cve_info["cve_id"])
                chart_data.append((host.get("host_name"), host.get("host_ip"), len(cve_set)))
                temp_file.write(content)
            return state.SUCCEED, temp_file_path, chart_data

    def _generate_cve_info_file(self) -> Tuple[str, List[Tuple[str, str, int]]]:
        """
        Generate an Excel table file containing CVE information and return host CVE number information.

        Args:
            username(str): The username.

        Returns:
            Tuple[str, List[Tuple[str, str, int]]]
            A tuple containing two elements (file generation status code, chart data).
            - File generation status code(str)
            - Chart data(List[Tuple[str, str, int]]): A list of host CVE number information
                For example: [("Host 1", "192.168.0.1", 5), ("Host 2", "192.168.0.2", 2)]
        """
        chart_data = []
        temp_file_path = None
        try:
            status, temp_file_path, chart_data = self.generate_temp_file()
        except OSError as error:
            LOGGER.error(error)
            return state.SERVER_ERROR, temp_file_path, chart_data

        return status, temp_file_path, chart_data


class NotificationTask:

    def execute(self) -> None:
        """
        handle for timed notification task
        """
        user_info = self._query_all_user_info()
        if user_info is None:
            return

        # example: {group_id:[host_info_1,host_info_2]}
        hosts_info = self.query_all_host_info()
        if not hosts_info:
            LOGGER.info("No host information was obtained, so email notification was stopped.")
            return

        with HostProxy() as proxy:
            for username, email in user_info.items():
                user_hosts_info = []
                user_permission_groups = self._quey_user_permission(username)
                if not user_permission_groups:
                    continue

                for group_id in user_permission_groups:
                    user_hosts_info.extend(hosts_info.get(group_id, []))
                EmailNoticeManager(username, proxy, user_hosts_info, email).send_email_to_user()

    @staticmethod
    def _get_response(method: str, url: str, params: dict = None) -> dict:
        """
        Send a request to the specified URL with the given parameters and return the response.

        Args:
            method (str): The HTTP method to use for the request (e.g., 'GET', 'POST').
            url (str): The URL to send the request to.
            params (dict, optional): The parameters to include in the request. Defaults to an empty dictionary if not provided.

        Returns:
            dict: The response data from the request.
        """
        if not params:
            params = {}

        signature = sign_data(params, load_private_key(cache.location_cluster.get("private_key")))
        headers = {"X-Permission": "RSA", "X-Signature": signature, "X-Cluster-Username": ADMIN_USER}
        query_url = f"http://{configuration.domain}{url}?{urlencode(params)}"
        return BaseResponse.get_response(method=method, url=query_url, header=headers)

    def _quey_user_permission(self, username: str) -> bool:
        """
        Query user permission

        Args:
            username(str): The username.

        Returns:
            list: An array containing the host group ids for which the user holds permissions
        """
        target_data = []

        response_data = self._get_response(method="GET", url=PERMISSIONS, params={"username": username})
        if response_data.get("label") != state.SUCCEED:
            LOGGER.warning(f"Failed to get user permission for {username}")
            return target_data

        for cluster_permission in response_data.get("data", []):
            for group in cluster_permission.get("host_groups"):
                target_data.append(group.get("host_group_id"))

        return target_data

    def _query_all_user_info(self):
        """
        query all user info
        """
        response_data = self._get_response(method="GET", url=USERS_ALL)
        if response_data.get("label") != state.SUCCEED:
            LOGGER.warning("Failed to get user info!")
            return {}

        # Expected return values: {user1:email1, user2:email2, user3:email3...}
        return {info.get("username"): info.get("email") for info in response_data.get("data", [])}

    def query_all_host_info(self):
        """
        Queries all host information and organizes it by host group ID.

        Returns:
            dict: A dictionary where the keys are host group IDs and the values are lists of host information
                  dictionaries containing host_id, host_ip, host_name, host_group_id, and cluster_id.
                  Returns an empty dictionary if the query fails.
        """

        target_result = defaultdict(list)

        # Query all host information
        request_args = {
            "fields": ["host_id", "host_ip", "host_name", "host_group_id", "cluster_id"],
        }
        response_data = self._get_response(method="GET", url=HOSTS_FILTER, params=request_args)
        if response_data.get("label") != state.SUCCEED:
            LOGGER.warning(f"Failed to query host information during timed notification task.")
            return target_result

        for host in response_data.get("data", []):
            target_result[host.get("host_group_id")].append(host)

        return target_result
