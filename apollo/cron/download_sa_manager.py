# !/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2023. All rights reserved.
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
import urllib.error
import urllib.request

import gevent
import retrying
import sqlalchemy
from retrying import retry
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import SUCCEED
from vulcanus.timed import TimedTask

from apollo.conf.constant import ADVISORY_SAVED_PATH
from apollo.database.proxy.cve import CveProxy
from apollo.function.customize_exception import ParseAdvisoryError
from apollo.handler.cve_handler.manager.parse_advisory import parse_security_advisory


class TimedDownloadSATask(TimedTask):
    """
    Timed download sa tasks
    """

    save_sa_record = []

    def __init__(self, timed_config):
        super().__init__(timed_config)
        self.cvrf_url = self.timed_config.get("meta", dict()).get("cvrf_url")

    @property
    def _advisory(self):
        return self.cvrf_url + "/index.txt"

    @property
    def _dirs(self):
        try:
            if os.path.exists(ADVISORY_SAVED_PATH):
                shutil.rmtree(ADVISORY_SAVED_PATH)
            os.makedirs(ADVISORY_SAVED_PATH)
            return True
        except IOError as error:
            LOGGER.error(error)
        return False

    def _execute_task(self, proxy: CveProxy):
        download_success_advisory, download_failed_advisory = proxy.get_advisory_download_record()
        if download_failed_advisory:
            proxy.delete_advisory_download_failed_record([record.id for record in download_failed_advisory])

        wait_download_advisory = self.get_incremental_sa_name_list(download_success_advisory)
        if not wait_download_advisory:
            LOGGER.warning("No security bulletin is waiting to be downloaded.")
            return

        # Limit the number of requests to 20 per time
        for i in range(0, len(wait_download_advisory), 20):
            wait_download_tasks = [
                gevent.spawn(self.download_security_advisory, advisory)
                for advisory in wait_download_advisory[i : i + 20]
            ]
            gevent.joinall(wait_download_tasks)

        self.save_security_advisory_to_database(proxy=proxy)

    def execute(self):
        """
        First read the downloaded history from the database, and then obtain the url list of the security announcements
        to be downloaded incrementally. Download all the security announcements in the list to the local, parse the
        security announcements and store them in the database, and update the data in the history table.
        """
        LOGGER.info("Begin to download advisory in %s.", str(datetime.datetime.now()))

        if not self.cvrf_url:
            LOGGER.error("Please add cvrf_url in configuration file.")
            return
        if not self._dirs:
            LOGGER.error("Create the temporary storage security directory failed.")
            return

        try:
            with CveProxy() as proxy:
                self._execute_task(proxy)
        except sqlalchemy.exc.SQLAlchemyError:
            LOGGER.error("Connect to database fail.")
            return
        finally:
            shutil.rmtree(ADVISORY_SAVED_PATH)

    def _record_download_result(self, year, serial_number, status):
        self.save_sa_record.append(
            {"advisory_year": year, "advisory_serial_number": serial_number, "download_status": status}
        )

    def save_security_advisory_to_database(self, proxy: CveProxy, advisory_dir=ADVISORY_SAVED_PATH):
        """
        Judge whether there are files in the folder. If there are, resolve the security announcement and save it in the
        database, and update the history; Otherwise, log prompts

        Args:
            proxy: database proxy
        """

        for file_name in os.listdir(advisory_dir):
            file_path = os.path.join(advisory_dir, file_name)
            advisory_year, advisory_serial_number = re.findall("\d+", file_name)
            try:
                cve_rows, cve_pkg_rows, cve_pkg_docs, _, _ = parse_security_advisory(file_path)
            except (KeyError, ParseAdvisoryError) as error:
                LOGGER.error(error)
                LOGGER.error("Some error occurred when parse advisory '%s'." % file_name)
                self._record_download_result(advisory_year, advisory_serial_number, False)
                continue

            save_status_code = proxy.save_security_advisory(file_name, cve_rows, cve_pkg_rows, cve_pkg_docs)
            status = True if save_status_code == SUCCEED else False
            self._record_download_result(advisory_year, advisory_serial_number, status)

        proxy.save_advisory_download_record(TimedDownloadSATask.save_sa_record)

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
            response = urllib.request.urlopen(url, timeout=30)
            return response.read()
        except urllib.error.HTTPError as e:
            LOGGER.info("Exception HTTPError %s" % e)
            return None
        except urllib.error.URLError as e:
            LOGGER.info("Exception URLError %s" % e)
            return ""

    def download_security_advisory(self, advisory: str):
        """
        Get each url from the list, download and save it locally, and save it to the database if the download fails

        Args:
            advisory: sa`s name, e.g. cvrf-openEuler-SA-2021-1022.xml
        """
        advisory_year, advisory_serial_number = re.findall("\d+", advisory)
        try:
            response = TimedDownloadSATask.get_response(f"{self.cvrf_url}/{advisory_year}/{advisory}")
            if response:
                with open(os.path.join(ADVISORY_SAVED_PATH, advisory), "wb") as file:
                    file.write(response)
                return

            LOGGER.error(f"Download failed: {advisory}")

        except retrying.RetryError:
            LOGGER.error(f"Download failed max retries: {advisory}")
        self._record_download_result(advisory_year, advisory_serial_number, False)

    def get_advisory_url_list(self) -> list:
        """
        Send a request and parse the data on the page to get all the security bulletins url and store them in the list

        Returns:
            list: security url list
        """
        try:
            response = TimedDownloadSATask.get_response(self._advisory)
            if response:
                sa_list = response.decode("utf-8").replace("\r", "").split("\n")
                # 2021/cvrf-openEuler-SA-2021-1022.xml, we don't need the first five characters
                return [sa_name[5:] for sa_name in sa_list]

        except retrying.RetryError:
            LOGGER.error("Downloading a security bulletin record error: %s" % TimedDownloadSATask.sa_records)

        return []

    def get_incremental_sa_name_list(self, download_succeed_record: list) -> list:
        """
        Get incremental information based on the data in the history table.

        First, obtain all the SA, subtracting the successful download is the increment

        Args:
             download_succeed_record: Download history record

        Returns:
            list: The name of the sa that needs to be downloaded
        """
        release_sa_names = self.get_advisory_url_list()
        if not release_sa_names:
            return []

        download_sa_names = [
            f"cvrf-openEuler-SA-{sa.advisory_year}-{sa.advisory_serial_number}.xml" for sa in download_succeed_record
        ]

        return list(set(release_sa_names) - set(download_sa_names))
