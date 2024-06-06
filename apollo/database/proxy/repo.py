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
Description: Host table operation
"""
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from vulcanus.database.helper import judge_return_code
from vulcanus.database.proxy import MysqlProxy
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import (
    DATABASE_DELETE_ERROR,
    DATABASE_INSERT_ERROR,
    NO_DATA,
    DATABASE_QUERY_ERROR,
    DATABASE_UPDATE_ERROR,
    DATA_EXIST,
    SUCCEED,
)

from apollo.database.table import Repo


class RepoProxy(MysqlProxy):
    """
    Repo related table operation
    """

    def import_repo(self, data):
        """
        Import repo

        Args:
            data(dict): parameter, e.g.
                {
                    "username": "admin",
                    "repo_name": "20.03-update",
                    "repo_data": ""
                }

        Returns:
            int: status code
        """
        try:
            status_code = self._insert_repo(data)
            if status_code == SUCCEED:
                self.session.commit()
                LOGGER.debug("Finished inserting new repo.")
            return status_code
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Insert new repo failed due to internal error.")
            return DATABASE_INSERT_ERROR

    def _insert_repo(self, data):
        """
        insert a repo into database
        Args:
            data (dict): repo info

        Returns:

        """
        repo_name = data["repo_name"]

        if self._if_repo_name_exists(repo_name, data["cluster_id"]):
            LOGGER.debug("Insert repo failed due to repo name already exists.")
            return DATA_EXIST

        # mock repo attr. Will get from request in the future
        data["repo_attr"] = ""

        repo = Repo(**data)
        self.session.add(repo)
        return SUCCEED

    def _if_repo_name_exists(self, repo_name, cluster_id):
        """
        if the repo name already exists in database
        Args:
            repo_name (str): repo name
            cluster_id (str): cluster id info of repo

        Returns:
            bool
        """
        repo_count = (
            self.session.query(func.count(Repo.repo_id))
            .filter(Repo.repo_name == repo_name, Repo.cluster_id == cluster_id)
            .scalar()
        )

        return True if repo_count else False

    def update_repo(self, data):
        """
        update repo

        Args:
            data(dict): parameter, e.g.
                {
                    "username": "admin",
                    "repo_name": "20.03-update",
                    "repo_data": ""
                }

        Returns:
            int: status code
        """
        try:
            status_code = self._update_repo(data)
            if status_code == SUCCEED:
                self.session.commit()
                LOGGER.debug("Finished Updating repo info.")
            return status_code
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Update repo info failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def _update_repo(self, data):
        """
        update a repo's into in database
        Args:
            data (dict): repo info

        Returns:

        """
        repo_name = data["repo_name"]

        if not self._if_repo_name_exists(repo_name, data.get("cluster_id")):
            LOGGER.debug("Update repo failed due to repo '%s' doesn't exist." % repo_name)
            return NO_DATA

        repo_data = data["repo_data"]
        # mock repo attr. Will get from request in the future
        repo_attr = ""

        repo_info = self.session.query(Repo).filter(Repo.repo_name == repo_name).one()
        repo_info.repo_data = repo_data
        repo_info.repo_attr = repo_attr

        return SUCCEED

    def get_repo(self, repo_id_list, cluster_id_list):
        """
        Get repo from database

        Args:
            repo_id_list(list): repo id list, e.g. ["repo_id_1","repo_id_2"]
            cluster_id_list(list): cluster id list

        Returns:
            str: status code
            dict: query result. e.g.
                {
                    "result": [
                        {
                            "repo_id": 1,
                            "repo_name": "20.03-update",
                            "repo_data": "[update]",
                            "repo_attr": "20.03"
                        },
                        {
                            "repo_id": 2,
                            "repo_name": "21.03-update",
                            "repo_data": "[update]",
                            "repo_attr": "21.03"
                        }
                    ]
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_repo(repo_id_list, cluster_id_list)
            LOGGER.debug("Finished querying repo info.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Querying repo info failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_repo(self, repo_id_list, cluster_id_list):
        """
        get processed repo data
        Args:
            repo_id_list (list): repo id list
            cluster_id_list(list): cluster id list

        Returns:
            status_code, list
        """
        repo_info_query = self._query_repo_list_info(repo_id_list, cluster_id_list)
        return SUCCEED, self._repo_info_row2dict(repo_info_query)

    def _query_repo_list_info(self, repo_list, cluster_id_list):
        """
        query repo info based on repo's id list
        Args:
            repo_list (list): repo id list, if repo list is empty, query all repo info
            cluster_id_list(list):  cluster id list, if cluster list is empty, query the repo of all clusters

        Returns:
            sqlalchemy.orm.query.Query
        """
        filters = set()
        if repo_list:
            filters.add(Repo.repo_id.in_(repo_list))
        if cluster_id_list:
            filters.add(Repo.cluster_id.in_(cluster_id_list))

        repo_info_query = self.session.query(Repo).filter(*filters)
        return repo_info_query

    @staticmethod
    def _repo_info_row2dict(rows):
        result = []
        for row in rows:
            repo_info = {
                "repo_id": row.repo_id,
                "repo_name": row.repo_name,
                "repo_data": row.repo_data,
                "repo_attr": row.repo_attr,
                "cluster_id": row.cluster_id,
            }
            result.append(repo_info)
        return result

    def delete_repo(self, repo_list, cluster_list) -> str:
        """
        Delete repo from database
        Notice, if a repo is still in use, all repo will not be deleted;
                if a repo doesn't exist, considered has been deleted successfully
        Args:
            repo_list (list): List of repository names to delete, e.g., ["20.09", "21.09"].
            cluster_list (list): List of cluster id, e.g., ["cluster1", "cluster2"].

        Returns:
            str: status code
        """
        try:
            self._query_repo_list_info(repo_list, cluster_list).delete(synchronize_session=False)
            self.session.commit()
            LOGGER.debug("Finished deleting repo info.")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Deleting repo info failed due to internal error.")
            return DATABASE_DELETE_ERROR
