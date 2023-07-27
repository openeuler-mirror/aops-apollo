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
    DATA_DEPENDENCY_ERROR,
)

from apollo.database.table import Repo, Host


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
        username = data["username"]

        if self._if_repo_name_exists(repo_name, username):
            LOGGER.debug("Insert repo failed due to repo name already exists.")
            return DATA_EXIST

        # mock repo attr. Will get from request in the future
        data["repo_attr"] = ""

        repo = Repo(**data)
        self.session.add(repo)
        return SUCCEED

    def _if_repo_name_exists(self, repo_name, username):
        """
        if the repo name already exists in database
        Args:
            repo_name (str): repo name
            username (str): user name

        Returns:
            bool
        """
        repo_count = (
            self.session.query(func.count(Repo.repo_id))
            .filter(Repo.repo_name == repo_name, Repo.username == username)
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
        username = data["username"]

        if not self._if_repo_name_exists(repo_name, username):
            LOGGER.debug("Update repo failed due to repo '%s' doesn't exist." % repo_name)
            return NO_DATA

        repo_data = data["repo_data"]
        # mock repo attr. Will get from request in the future
        repo_attr = ""

        repo_info = self.session.query(Repo).filter(Repo.username == username, Repo.repo_name == repo_name).one()
        repo_info.repo_data = repo_data
        repo_info.repo_attr = repo_attr

        return SUCCEED

    def get_repo(self, data):
        """
        Get repo from database

        Args:
            data(dict): parameter, e.g.
                {
                    "repo_name_list": [],  // if empty, get all repo
                    "username": "admin"
                }

        Returns:
            int: status code
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
            status_code, result = self._get_processed_repo(data)
            LOGGER.debug("Finished querying repo info.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Querying repo info failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_repo(self, data):
        """
        get processed repo data
        Args:
            data (dict): parameter

        Returns:
            status_code, list
        """
        repo_list = data["repo_name_list"]
        username = data["username"]

        repo_info_query = self._query_repo_list_info(username, repo_list)
        result = self._repo_info_row2dict(repo_info_query)

        succeed_list = [row.repo_name for row in repo_info_query]
        fail_list = list(set(repo_list) - set(succeed_list))

        if fail_list:
            LOGGER.debug("No data found when getting the info of repo: %s." % fail_list)

        status_dict = {"succeed_list": succeed_list, "fail_list": fail_list}
        status_code = judge_return_code(status_dict, NO_DATA)
        return status_code, {"result": result}

    def _query_repo_list_info(self, username, repo_list):
        """
        query repo info based on repo's name list
        Args:
            username (str): user name
            repo_list (list): repo name list, when empty, query all repo info

        Returns:
            sqlalchemy.orm.query.Query
        """
        filters = {Repo.username == username}
        if repo_list:
            filters.add(Repo.repo_name.in_(repo_list))

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
            }
            result.append(repo_info)
        return result

    def delete_repo(self, data):
        """
        Delete repo from database
        Notice, if a repo is still in use, all repo will not be deleted;
                if a repo doesn't exist, considered has been deleted successfully
        Args:
            data(dict): parameter, e.g.
                {
                    "repo_name_list": ["20.09", "21.09"],
                    "username": ""admin
                }

        Returns:
            int: status code
        """
        try:
            status_code = self._delete_repo(data)
            if status_code == SUCCEED:
                self.session.commit()
                LOGGER.debug("Finished deleting repo info.")
            return status_code
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Deleting repo info failed due to internal error.")
            return DATABASE_DELETE_ERROR

    def _delete_repo(self, data):
        """
        delete repo list from database
        Args:
            data (dict): repo name list info

        Returns:
            int: status code
        """
        repo_list = data["repo_name_list"]
        username = data["username"]

        fail_list = self._get_repo_in_use(username, repo_list)
        if fail_list:
            LOGGER.debug("Repos are still in use when deleting repo: %s." % fail_list)
            return DATA_DEPENDENCY_ERROR

        # query and delete.
        # delete() is not applicable to 'in_' method without synchronize_session=False
        self._query_repo_list_info(username, repo_list).delete(synchronize_session=False)
        return SUCCEED

    def _get_repo_in_use(self, username, repo_list):
        """
        get the repo in use
        Args:
            username (str): user name
            repo_list (list): repo name list

        Returns:
            list
        """
        repo_in_use_query = (
            self.session.query(Host.repo_name)
            .filter(Host.repo_name.in_(repo_list))
            .filter(Host.user == username)
            .group_by(Host.repo_name)
        )
        repo_in_use = [row.repo_name for row in repo_in_use_query]
        return repo_in_use
