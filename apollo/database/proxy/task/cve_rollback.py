#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
# licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN 'AS IS' BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/
from typing import Tuple

from sqlalchemy.exc import SQLAlchemyError
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import (
    DATABASE_INSERT_ERROR,
    NO_DATA,
    SUCCEED,
    PARAM_ERROR
)

from apollo.conf.constant import TaskType
from apollo.database.proxy.task.base import TaskProxy
from apollo.database.table import CveFixTask


class CveRollbackTask(TaskProxy):

    def generate_cve_rollback_task(self, data: dict) -> Tuple[int, str or None]:
        """
        For generating, save cve rollback task basic info to mysql, init task info in es.

        Args:
            data (dict): e.g.
                {
                    "username": "admin",
                    "task_id": "",
                    "fix_task_id": "",
                    "task_type": "",
                    "create_time": 1
                }

        Returns:
            int: status code
        """
        try:
            status_code, msg = self._generate_cve_rollback_task(data)
            if status_code != SUCCEED:
                return status_code, msg
            self.session.commit()
            LOGGER.debug("Finished generating cve task.")
            return status_code, msg
        except (SQLAlchemyError, KeyError) as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Generating cve task failed due to internal error.")
            return DATABASE_INSERT_ERROR, None

    def _generate_cve_rollback_task(self, data) -> Tuple[int, str or None]:
        fix_task_id = data["fix_task_id"]
        fix_task_basic_info = self._query_task_basic_info(fix_task_id).first()
        fix_task_info = self.session.query(CveFixTask).filter(
            CveFixTask.task_id == fix_task_id).all()
        if not all([fix_task_basic_info, fix_task_info]):
            msg = "No data found when getting the info of cve task for rollback: %s." % fix_task_id
            LOGGER.debug(msg)
            return NO_DATA, msg

        if fix_task_basic_info.task_type != TaskType.CVE_FIX:
            msg = "Task '%s' is '%s' task, cannot be rolled back." % (fix_task_id, fix_task_basic_info.task_type)
            LOGGER.debug(msg)
            return PARAM_ERROR, msg
        # TODO

        return SUCCEED, None
