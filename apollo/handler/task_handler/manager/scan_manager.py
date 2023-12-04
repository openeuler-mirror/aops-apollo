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
Description: Task manager for cve scanning.
"""
import re
import time
from collections import defaultdict
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from io import BytesIO
from typing import List

from vulcanus.conf.constant import URL_FORMAT
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import SUCCEED, TASK_EXECUTION_FAIL
from vulcanus.restful.response import BaseResponse
from vulcanus.send_email import Email

from apollo.conf import configuration
from apollo.conf.constant import EXECUTE_CVE_SCAN, VUL_TASK_CVE_SCAN_CALLBACK
from apollo.database.proxy.task.base import TaskProxy
from apollo.handler.task_handler.manager import Manager


class ScanManager(Manager):
    """
    Manager for scanning task
    """

    def __init__(self, task_id, proxy, host_info, username, timed=False):
        """
        Args:
            task_id (str)
            proxy (object): proxy object of the database
            host_info (list)
            username (str)
        """
        self.host_list = [host['host_id'] for host in host_info]
        self.username = username
        self.pattern = re.compile(r'CVE-\d+-\d+')
        self._timed = timed
        super().__init__(proxy, task_id)

    def create_task(self):
        """
        Returns:
            int: status code
        """
        host_info_list = []
        for host_id in self.host_list:
            host_info_list.append({"host_id": host_id, "check": False})

        self.task = {
            "task_id": self.task_id,
            "task_type": "cve scan",
            "total_hosts": self.host_list,
            "check_items": [],
            "callback": VUL_TASK_CVE_SCAN_CALLBACK,
        }

        return SUCCEED

    def pre_handle(self):
        """
        Init host scan status.

        Returns:
            bool
        """
        if self.proxy.update_host_scan("init", self.host_list, self.username) != SUCCEED:
            LOGGER.error("Init the host status in database failed, stop scanning.")
            return False

        return True

    def handle(self):
        """
        Execute cve scan task.
        """
        LOGGER.info("Scanning task %s start to execute.", self.task_id)
        manager_url = URL_FORMAT % (configuration.zeus.get('IP'), configuration.zeus.get('PORT'), EXECUTE_CVE_SCAN)
        header = {"access_token": self.token, "Content-Type": "application/json; charset=UTF-8"}
        if self._timed:
            header.update(
                {
                    "exempt_authentication": configuration.individuation.get("EXEMPT_AUTHENTICATION"),
                    "local_account": self.username,
                }
            )

        response = BaseResponse.get_response('POST', manager_url, self.task, header)
        if response.get('label') != SUCCEED:
            LOGGER.error("Cve scan task %s execute failed.", self.task_id)
            return TASK_EXECUTION_FAIL
        return SUCCEED


class EmailNoticeManager:
    """
    email notice method manager
    """

    def __init__(self, username: str, proxy: TaskProxy) -> None:
        self.username = username
        self.proxy = proxy

    def send_email_to_user(self) -> None:
        """
        send email to user with cve scan result
        """
        # Get config info
        server = configuration.email.get("SERVER")
        port = configuration.email.get("PORT")
        authorization_code = configuration.email.get("AUTHORIZATION_CODE")
        sender = configuration.email.get("SENDER")

        # Get user email address
        status, receiver = self.proxy.query_user_email(self.username)
        if status != SUCCEED:
            LOGGER.warning(f"Query {self.username} email address failed!Can't send email")
            return

        # Generate email body
        message = self._generate_email_body(sender, receiver)

        # send email
        email_obj = Email(server, port, sender, authorization_code)
        email_obj.send(receiver, message)

    def _generate_email_body(self, sender: str, receivers: str) -> MIMEMultipart:
        """
        The function used to generate email content

        Args:
            sender: Email Sender
            receivers: The recipient of the email

        Return:
            MIMEMultipart: Mail Object
        """
        message = MIMEMultipart('mixed')
        status, host_cve_info_list = self.proxy.query_host_cve_info(self.username)
        if status != SUCCEED:
            return message

        # set email subject
        message['Subject'] = f'{time.strftime("【%Y-%m-%d", time.localtime())}' f' A-OPS】CVE扫描结果'
        message['From'] = f'A-OPS<{sender}>'
        message['To'] = receivers

        # set email text content and file content
        file, table_data = self._generate_cve_info_file(host_cve_info_list)

        body_head = "<p>下表为各主机CVE扫描结果简略统计表：</p>"
        body_tail = (
            f'<p>详细CVE信息请查看附件。</p>'
            f'<a href="http://{configuration.hermes.get("IP")}:'
            f'{configuration.hermes.get("PORT")}/'
            f'leaks/host-leak-list">点击跳转AOPS</a>'
        )
        table_title = ["序号", "主机名", "主机IP", "CVE个数"]
        html = f"{body_head}{Email.turn_data_to_table_html(table_title, table_data)}{body_tail}"
        text_content = MIMEText(html, "html", "utf-8")
        message.attach(text_content)

        file_content = MIMEApplication(file.read())
        file_content.add_header(
            'Content-Disposition', 'attachment', filename=f"CVE_{time.strftime('%Y_%m_%d', time.localtime())}.csv"
        )
        message.attach(file_content)

        return message

    def _generate_cve_info_file(self, host_cve_info_list: List[dict]) -> tuple:
        """
        Generate CSV files and email content for cve information

        Args:
            host_cve_info_list(list): Information on host and cve found from the database.e.g
                {
                    "host_id": 1,
                    "host_ip": "127.0.0.1",
                    "host_name": "client",
                    "cve_id": "CVE-XXXX-XXXX",
                    "cvss_score": 7.5,
                    "severity": "Important",
                    "installed_rpm": "rpm-name-6.2.5-1.x86_64",
                    "source_package": {"rpm-name.src.rpm"},
                    "available_rpms": {"rpm-name-6.2.5-2.x86_64","patch-rpm-name-6.2.5-1-ACC...."},
                    "support_ways": {"hotpatch", "coldpatch"},
                }

        Return:
            BytesIO: Generate CSV files
            list: email content for cve information
        """
        host_cve_count, host_info = defaultdict(set), {}
        chart_data = []
        file_content = "序号,主机IP,主机名称,CVE_ID,CVSS评分,评分级别,受影响软件包(source),受影响软件包(rpm),可安装修复包,修复方式\n"
        excel_row_num = 1

        for info in host_cve_info_list:
            if info["host_id"] not in host_info:
                host_info[info["host_id"]] = (info["host_name"], info["host_ip"])

            if info.get("cve_id"):
                host_cve_count[info["host_id"]].add(info["cve_id"])
            else:
                host_cve_count[info["host_id"]]
                continue

            file_content += (
                f'{excel_row_num},{info["host_ip"]},{info["host_name"]},{info["cve_id"]},{info["cvss_score"]},'
                f'{info["severity"]},{";".join(info["source_package"])},{info["installed_rpm"]},'
                f'{";".join(info["available_rpms"])},{";".join(info["support_ways"])},\n'
            )
            excel_row_num += 1

        for serial_number, host_cve_count_info in enumerate(host_cve_count.items(), 1):
            host_id = host_cve_count_info[0]
            chart_data.append(
                [
                    serial_number,
                    host_info.get(host_id)[0],
                    host_info.get(host_id)[1],
                    len(host_cve_count_info[1]),
                ]
            )

        return self._generate_file_object(file_content), chart_data

    @staticmethod
    def _generate_file_object(content: str) -> BytesIO:
        """
        Generate BytesIO object

        Args:
            content(str): text content

        Returns:
            BytesIO
        """
        file = BytesIO()
        file.write(content.encode("utf-8"))
        file.seek(0)
        return file
