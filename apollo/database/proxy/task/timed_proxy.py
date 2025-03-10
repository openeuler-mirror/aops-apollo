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
from sqlalchemy.exc import SQLAlchemyError
from vulcanus.database.proxy import MysqlProxy
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import DATABASE_UPDATE_ERROR, SUCCEED

from apollo.conf.constant import TaskStatus
from apollo.database.table import CveFixTask, CveRollbackTask, HotpatchRemoveTask, TaskHostRepoAssociation


class TimedProxy(MysqlProxy):
    def timed_correct_error_task_status(self, task_ids):
        """
        Change the status of the exception task to unknown

        Args:
            task_ids: task id list
        Returns:
            str: status_code
        """
        try:
            self.session.query(HotpatchRemoveTask).filter(HotpatchRemoveTask.task_id.in_(task_ids)).update(
                {HotpatchRemoveTask.status: TaskStatus.UNKNOWN}, synchronize_session=False
            )
            self.session.query(TaskHostRepoAssociation).filter(TaskHostRepoAssociation.task_id.in_(task_ids)).update(
                {TaskHostRepoAssociation.status: TaskStatus.UNKNOWN}, synchronize_session=False
            )
            self.session.query(CveFixTask).filter(CveFixTask.task_id.in_(task_ids)).update(
                {CveFixTask.status: TaskStatus.UNKNOWN}, synchronize_session=False
            )
            self.session.query(CveRollbackTask).filter(CveRollbackTask.task_id.in_(task_ids)).update(
                {CveRollbackTask.status: TaskStatus.UNKNOWN}, synchronize_session=False
            )
            self.session.commit()
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Scheduled task status correction failed.")
            return DATABASE_UPDATE_ERROR
        return SUCCEED
