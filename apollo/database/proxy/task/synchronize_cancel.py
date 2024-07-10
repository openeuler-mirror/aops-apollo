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
from vulcanus.restful.resp.state import (
    DATABASE_DELETE_ERROR,
    SUCCEED,
)

from apollo.database.table import (
    Task,
    HotpatchRemoveTask,
    TaskHostRepoAssociation,
    CveFixTask,
    CveRollbackTask,
    Repo,
    CveHostAssociation,
)


class SynchronizeCancelProxy(MysqlProxy):
    def delete_cluster_info(self, cluster_id):
        """
        delete cluster info

        Args:
            cluster_id: cluster_id
        Returns:
            str: status_code
        """
        try:
            task_ids = [row.task_id for row in
                        self.session.query(Task.task_id).filter(Task.cluster_id == cluster_id).all()]
            self.session.query(HotpatchRemoveTask).filter(HotpatchRemoveTask.task_id.in_(task_ids)).delete(synchronize_session=False)
            self.session.query(TaskHostRepoAssociation).filter(TaskHostRepoAssociation.task_id.in_(task_ids)).delete(synchronize_session=False)
            self.session.query(CveFixTask).filter(CveFixTask.task_id.in_(task_ids)).delete(synchronize_session=False)
            self.session.query(CveRollbackTask).filter(CveRollbackTask.task_id.in_(task_ids)).delete(synchronize_session=False)
            self.session.query(Task).filter(Task.cluster_id == cluster_id).delete(synchronize_session=False)
            self.session.query(Repo).filter(Repo.cluster_id == cluster_id).delete(synchronize_session=False)
            self.session.query(CveHostAssociation).filter(CveHostAssociation.cluster_id == cluster_id).delete(synchronize_session=False)

            self.session.commit()
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("delete cluster %s info fail", cluster_id)
            return DATABASE_DELETE_ERROR
        return SUCCEED
