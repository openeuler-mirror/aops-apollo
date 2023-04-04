# !/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
# licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/
import datetime
import os
import re
import shutil

import requests
import retrying
from lxml import etree
from requests.exceptions import ConnectTimeout
from retrying import retry

from apollo.conf import configuration
from apollo.conf.constant import ADVISORY_SAVED_PATH, TIMED_TASK_CONFIG_PATH
from apollo.cron import TimedTaskBase
from apollo.cron.manager import get_timed_task_config_info
from apollo.database import session_maker
from apollo.database.proxy.cve import CveProxy
from apollo.function.customize_exception import ParseAdvisoryError
from apollo.handler.cve_handler.manager.parse_advisory import parse_security_advisory
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import SUCCEED


class TimedDownloadSATask(TimedTaskBase):
    """
    Timed download sa tasks
    """
    config_info = get_timed_task_config_info(TIMED_TASK_CONFIG_PATH)
    security_base_url = config_info.get("download_sa", dict()).get("base_url", "")
    if not security_base_url:
        LOGGER.error("Please add base_url in configuration file")
    advisory_years = config_info.get("download_sa", dict()).get("sa_years", "")
    if advisory_years:
        advisory_years = re.findall(r"\d{4}", advisory_years)
    else:
        LOGGER.error("Please add sa_years in configuration file")
        raise KeyError

    save_sa_record = []

    @staticmethod
    def task_enter():
        """
        First read the downloaded history from the database, and then obtain the url list of the security announcements
        to be downloaded incrementally. Download all the security announcements in the list to the local, parse the
        security announcements and store them in the database, and update the data in the history table.
        """
        LOGGER.info("Begin to download advisory in %s.", str(datetime.datetime.now()))
        proxy = CveProxy(configuration)
        if not proxy.connect(session_maker()):
            LOGGER.error("Connect to database fail.")
            return
        download_record, download_failed_advisory = proxy.get_advisory_download_record()

        sa_name_list = TimedDownloadSATask.get_incremental_sa_name_list(download_record)

        TimedDownloadSATask.download_security_advisory(sa_name_list)
        TimedDownloadSATask.save_security_advisory_to_database(proxy)

        proxy.save_advisory_download_record(TimedDownloadSATask.save_sa_record)

        if download_failed_advisory:
            id_list = [record.id for record in download_failed_advisory]
            proxy.delete_advisory_download_failed_record(id_list)

    @staticmethod
    def save_security_advisory_to_database(proxy):
        """
        Judge whether there are files in the folder. If there are, resolve the security announcement and save it in the
        database, and update the history; Otherwise, log prompts

        Args:
            proxy: database proxy
        """
        advisory_dir = os.listdir(ADVISORY_SAVED_PATH)
        if len(advisory_dir) <= 0:
            LOGGER.info("no advisory security need to parse")
            return

        for file_name in advisory_dir:
            file_path = os.path.join(ADVISORY_SAVED_PATH, file_name)
            advisory_year, advisory_serial_number = re.findall("\d+", file_name)
            try:
                cve_rows, cve_pkg_rows, cve_pkg_docs, sa_year, sa_number = parse_security_advisory(file_path)
            except (KeyError, ParseAdvisoryError) as error:
                LOGGER.error(error)
                LOGGER.error("Some error occurred when parse advisory '%s'." % file_name)
                TimedDownloadSATask.save_sa_record.append({"advisory_year": advisory_year,
                                                           "advisory_serial_number": advisory_serial_number,
                                                           "download_status": False})
                continue
            save_status_code = proxy.save_security_advisory(file_name, cve_rows, cve_pkg_rows, cve_pkg_docs)
            TimedDownloadSATask.save_sa_record.append({"advisory_year": advisory_year,
                                                       "advisory_serial_number": advisory_serial_number,
                                                       "download_status": True if save_status_code == SUCCEED else False})

        shutil.rmtree(ADVISORY_SAVED_PATH)
        LOGGER.info("delete save path when parse succeed")

    @staticmethod
    @retry(retry_on_result=lambda result: result is None, stop_max_attempt_number=3)
    def get_response(url: str):
        """
        Get request response body
        Args:
            url(str): Request Address
        Returns:
            response body or "", "" means request failed
        """
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != requests.codes["ok"]:
                return None
            return response
        except requests.exceptions.RequestException:
            return ""

    @staticmethod
    def download_security_advisory(sa_name_list: list):
        """
        Get each url from the list, download and save it locally, and save it to the database if the download fails

        Args:
            sa_name_list: Advisory url list, each element is the url of the security announcement
        """
        if os.path.exists(ADVISORY_SAVED_PATH):
            shutil.rmtree(ADVISORY_SAVED_PATH)
        os.makedirs(ADVISORY_SAVED_PATH)

        for sa_name in sa_name_list:
            advisory_year, advisory_serial_number = re.findall("\d+", sa_name)
            sa_url = f"{TimedDownloadSATask.security_base_url}/{advisory_year}/{sa_name}"
            try:
                response = TimedDownloadSATask.get_response(sa_url)
                if response:
                    with open(os.path.join(ADVISORY_SAVED_PATH, sa_name), "wb")as w:
                        w.write(response.content)
                else:
                    LOGGER.error(f"Download failed request timeout: {sa_name}")
                    TimedDownloadSATask.save_sa_record.append({"advisory_year": advisory_year,
                                                               "advisory_serial_number": advisory_serial_number,
                                                               "download_status": False})
            except retrying.RetryError:
                LOGGER.error(f"Download failed max retries: {sa_name}")
                TimedDownloadSATask.save_sa_record.append({"advisory_year": advisory_year,
                                                           "advisory_serial_number": advisory_serial_number,
                                                           "download_status": False})

    @staticmethod
    def get_advisory_url_list(url: str) -> list:
        """
        Send a request and parse the data on the page to get all the security bulletins url and store them in the list

        Args:
            url(str): the url of all security announcements

        Returns:
            list: security url list
        """
        try:
            response = TimedDownloadSATask.get_response(url)
            if response:
                html = etree.HTML(response.text)
                security_files = [
                    file for file in html.xpath("//*[@id='list']/tbody/tr/td[1]/a/@title")
                ]
                return security_files
            else:
                return []
        except retrying.RetryError:
            return []

    @staticmethod
    def get_incremental_sa_name_list(download_succeed_record: list) -> list:
        """
        Get incremental information based on the data in the history table.

        First, obtain all the SA, subtracting the successful download is the increment

        Args:
             download_succeed_record: Download history record

        Returns:
            list: The name of the sa that needs to be downloaded
        """
        today = datetime.datetime.today()
        current_year = str(today.year)
        TimedDownloadSATask.advisory_years.append(current_year)
        all_sa_name_list = []

        for year in set(TimedDownloadSATask.advisory_years):
            try:
                sa_name_list = TimedDownloadSATask.get_advisory_url_list(
                    TimedDownloadSATask.security_base_url + "/" + str(year) + "/")
                all_sa_name_list.extend(sa_name_list)
            except retrying.RetryError:
                LOGGER.error(f"Failed to get the {year} sa file")

        succeed_sa_name_list = []
        for succeed_record in download_succeed_record:
            succeed_sa_name = f"cvrf-openEuler-SA-{succeed_record.advisory_year}-{succeed_record.advisory_serial_number}.xml"
            succeed_sa_name_list.append(succeed_sa_name)
        increment_sa = set(all_sa_name_list) - set(succeed_sa_name_list)

        return list(increment_sa)
