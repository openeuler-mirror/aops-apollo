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
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func, case, or_, and_

from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import NO_DATA, DATABASE_QUERY_ERROR, SUCCEED
from vulcanus.database.helper import sort_and_page, judge_return_code
from vulcanus.database.proxy import MysqlProxy
from vulcanus.database.table import Host
from apollo.database.table import Cve, CveHostAssociation
from apollo.database.proxy.cve import CveEsProxy


class HostMysqlProxy(MysqlProxy):
    """
    Host related table operation
    """

    def get_host_list(self, data):
        """
        Get hosts which have cve of a specific user from table

        Args:
            data(dict): parameter, e.g.
                {
                    "sort": "last_scam",
                    "direction": "asc",
                    "page": 1,
                    "per_page": 10,
                    "username": "admin",
                    "filter": {
                        "host_name": "host1",
                        "host_group": ["group1"],
                        "repo": ["21.09"],
                        "status": ["scanning"]
                    }
                }

        Returns:
            int: status code
            dict: query result. e.g.
                {
                    "total_count": 1,
                    "total_page": 1,
                    "result": [
                        {
                            "host_id": 1,
                            "host_name": "name1",
                            "host_ip": "1.1.1.1",
                            "host_group": "group1",
                            "repo": "20.03-update",
                            "cve_num": 12,
                            "last_scan": 1111111111
                        }
                    ]
                }
        """
        result = {}
        try:
            result = self._get_processed_host_list(data)
            LOGGER.debug("Finished getting host list.")
            return SUCCEED, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting host list failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_host_list(self, data):
        """
        Get sorted and filtered host list.

        Args:
            data(dict): sort, page and filter info

        Returns:
            dict
        """
        result = {
            "total_count": 0,
            "total_page": 1,
            "result": []
        }

        filters = self._get_host_list_filters(data.get("filter"), data.get("username"))
        host_query = self._query_host_list(filters)

        total_count = host_query.count()
        if not total_count:
            return result

        sort_column = self._get_host_list_sort_column(data.get('sort'), host_query)
        direction, page, per_page = data.get('direction'), data.get('page'), data.get('per_page')

        processed_query, total_page = sort_and_page(host_query, sort_column, direction, per_page, page)

        host_rows = processed_query.all()
        result['result'] = self._host_list_row2dict(host_rows)
        result['total_page'] = total_page
        result['total_count'] = total_count

        return result

    @staticmethod
    def _get_host_list_sort_column(column_name, query=None):
        """
        get column or aggregation column of table by name
        Args:
            column_name (str/None): name of column

        Returns:
            column or aggregation column of table, or None if column name is not given
        """
        if not column_name:
            return None
        if column_name == "cve_num" and query is not None:
            return query.c.cve_num
        return getattr(Host, column_name)

    def _query_host_list(self, filters):
        """
        query needed host info, regardless the host has cve or not
        Args:
            filters (set): filter given by user

        Returns:
            sqlalchemy.orm.query.Query
        """
        return self.session.query(
            Host.host_id, Host.host_name, Host.host_ip, Host.host_group_name, Host.repo_name, Host.last_scan,
            func.COUNT(func.IF(CveHostAssociation.fixed == True, 1, None)).label("fixed_cve_num"),
            func.COUNT(func.IF(CveHostAssociation.fixed == False, 1, None)).label("unfixed_cve_num")) \
            .outerjoin(CveHostAssociation, Host.host_id == CveHostAssociation.host_id) \
            .group_by(Host.host_id) \
            .filter(*filters)

    @staticmethod
    def _host_list_row2dict(rows):
        result = []
        for row in rows:
            host_info = {
                "host_id": row.host_id,
                "host_name": row.host_name,
                "host_ip": row.host_ip,
                "host_group": row.host_group_name,
                "repo": row.repo_name,
                "unfixed_cve_num": row.unfixed_cve_num,
                "fixed_cve_num": row.fixed_cve_num,
                "last_scan": row.last_scan
            }
            result.append(host_info)
        return result

    @staticmethod
    def _get_host_list_filters(filter_dict, username):
        """
        Generate filters

        Args:
            filter_dict(dict): filter dict to filter cve list, e.g.
                {
                    "host_name": "host1",
                    "host_group": ["group1", "group2"],
                    "repo": ["repo1"]
                }
            username (str): user name of the request
        Returns:
            set
        """
        filters = {Host.user == username}
        if not filter_dict:
            return filters

        if filter_dict.get("host_name"):
            filters.add(Host.host_name.like(
                "%" + filter_dict["host_name"] + "%"))
        if filter_dict.get("host_group"):
            filters.add(Host.host_group_name.in_(filter_dict["host_group"]))
        if filter_dict.get("repo"):
            repos = [repo if repo else None for repo in filter_dict["repo"]]
            if None in repos:
                filters.add(or_(Host.repo_name.is_(None),
                                Host.repo_name.in_(repos)))
            else:
                filters.add(Host.repo_name.in_(repos))

        return filters

    def get_hosts_status(self, data):
        """
        Get hosts status

        Args:
            data(dict): parameter, e.g.
                {
                    "host_list": [1],  // if empty, query all hosts
                    "username": "admin"
                }

        Returns:
            int: status code
            dict: hosts' status. e.g.
                {
                    "result": {
                        "id1": "scanning",
                        "id2": "done"
                    }
                }
        """
        result = {}

        try:
            status_code, result = self._get_processed_hosts_status(data)
            LOGGER.debug("Finished getting host status.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting host status failed due to internal error")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_hosts_status(self, data):
        """
        Query and process host status
        Args:
            data (dict): host list info

        Returns:
            int: status code of operation
            dict: status of each host
        """
        username = data["username"]
        host_list = data["host_list"]
        result = {}

        hosts_status_query = self._query_hosts_status(username, host_list)

        succeed_list = []
        for row in hosts_status_query:
            result[row.host_id] = row.status
            succeed_list.append(row.host_id)

        fail_list = list(set(host_list) - set(succeed_list))
        if fail_list:
            LOGGER.debug(
                "No data found when getting the status of host: %s." % fail_list)

        status_dict = {"succeed_list": succeed_list, "fail_list": fail_list}
        status_code = judge_return_code(status_dict, NO_DATA)
        return status_code, {"result": result}

    def _query_hosts_status(self, username, host_list):
        """
        query hosts status info from database
        Args:
            username (str): user name
            host_list (list): host id list, when empty, query all hosts

        Returns:
            sqlalchemy.orm.query.Query

        """
        filters = {Host.user == username}
        if host_list:
            filters.add(Host.host_id.in_(host_list))

        hosts_status_query = self.session.query(
            Host.host_id, Host.status).filter(*filters)
        return hosts_status_query

    def get_host_info(self, data):
        """
        Get host info

        Args:
            data(dict): parameter, e.g.
                {
                    "username": "admin",
                    "host_id": 1
                }

        Returns:
            int: status code
            dict: host's info. e.g.
                {
                    "result": {
                        "host_name": "name1",
                        "host_ip": "1.1.1.1",
                        "host_group": "group1",
                        "repo": "20.03-update",
                        "affected_cve_num": 12,
                        "unaffected_cve_num": 1,
                        "last_scan": 1111111111
                    }
                }
        """
        result = {}

        try:
            status_code, result = self._get_processed_host_info(data)
            LOGGER.debug("Finished getting host info.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting host info failed due to internal error")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_host_info(self, data):
        """
        query and process host info
        Args:
            data (dict): {"host_id": 1, "username": "admin"}

        Returns:
            int: status code
            dict: query result

        Raises:
            sqlalchemy.orm.exc.MultipleResultsFound
        """
        host_id = data["host_id"]
        username = data["username"]

        host_info_query = self._query_host_info(username, host_id)
        if not host_info_query.count():
            LOGGER.debug(
                "No data found when getting the info of host: %s." % host_id)
            return NO_DATA, {"result": {}}

        # raise exception when multiple record found
        host_info_data = host_info_query.one()

        info_dict = self._host_info_row2dict(host_info_data)
        return SUCCEED, {"result": info_dict}

    def _query_host_info(self, username, host_id):
        """
        query needed host info
        Args:
            username (str): user name of the request
            host_id (int): host id

        Returns:
            sqlalchemy.orm.query.Query
        """
        return self.session.query(
            Host.host_id, Host.host_name, Host.host_ip, Host.host_group_name, Host.repo_name, Host.last_scan,
            func.COUNT(func.IF(CveHostAssociation.fixed == True, 1, None)).label("fixed_cve_num"),
            func.COUNT(func.IF(and_(CveHostAssociation.fixed == False, CveHostAssociation.affected == True), 1, None) ).label("affected_cve_num"), \
            func.COUNT(func.IF(and_(CveHostAssociation.fixed == False, CveHostAssociation.affected == False), 1, None) ).label("unaffected_cve_num")) \
            .outerjoin(CveHostAssociation, Host.host_id == CveHostAssociation.host_id) \
            .group_by(Host.host_id) \
            .filter(Host.user == username, Host.host_id == host_id)

    @staticmethod
    def _host_info_row2dict(row):
        host_info = {
            "host_name": row.host_name,
            "host_ip": row.host_ip,
            "host_group": row.host_group_name,
            "repo": row.repo_name,
            "affected_cve_num": row.affected_cve_num,
            "unaffected_cve_num": row.unaffected_cve_num,
            "last_scan": row.last_scan,
            "fixed_cve_num": row.fixed_cve_num
        }
        return host_info


class HostProxy(HostMysqlProxy, CveEsProxy):
    """
    Host related database operation
    """

    def __init__(self, configuration, host=None, port=None):
        """
        Instance initialization

        Args:
            configuration (Config)
            host(str)
            port(int)
        """
        HostMysqlProxy.__init__(self, configuration)
        CveEsProxy.__init__(self, configuration, host, port)

    def connect(self):
        return CveEsProxy.connect(self)

    def close(self):
        CveEsProxy.close(self)

    def __del__(self):
        CveEsProxy.__del__(self)

    def get_host_cve(self, data):
        """
        Get cve info of a host

        Args:
            data(dict): parameter, e.g.
                {
                    "host_id": 1,
                    "sort": "publish_time",
                    "direction": "asc",
                    "page": 1,
                    "per_page": 10,
                    "username": "admin",
                    "filter": {
                        "cve_id": "",
                        "severity": ["high"],
                        "affected": True,
                        "fixed": True
                    }
                }

        Returns:
            int: status code
            dict: query result. e.g.
                {
                    "total_count": 1,
                    "total_page": 1,
                    "result": [
                        {
                            "cve_id": "id1",
                            "publish_time": "2020-09-24",
                            "severity"; "high",
                            "description": "a long description",
                            "cvss_score": "7.2",
                            "hotpatch": true/false
                        }
                    ]
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_host_cve(data)
            LOGGER.debug("Finished getting host's CVEs.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting host's CVEs failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_host_cve(self, data):
        """
        Query and process host's CVEs data
        Args:
            data (dict): query condition

        Returns:
            int: status code
            dict: processed query result
        """
        result = {
            "total_count": 0,
            "total_page": 1,
            "result": []
        }

        host_id = data["host_id"]
        filters = self._get_host_cve_filters(data.get("filter", {}))
        host_cve_query = self._query_host_cve(
            data["username"], host_id, filters)

        total_count = host_cve_query.count()
        if not total_count:
            return SUCCEED, result

        sort_column = getattr(Cve, data['sort']) if "sort" in data else None
        direction, page, per_page = data.get(
            'direction'), data.get('page'), data.get('per_page')

        processed_query, total_page = sort_and_page(host_cve_query, sort_column,
                                                    direction, per_page, page)
        description_dict = self._get_cve_description(
            [row.cve_id for row in processed_query])

        result['result'] = self._host_cve_row2dict(
            processed_query, description_dict)
        result['total_page'] = total_page
        result['total_count'] = total_count

        return SUCCEED, result

    @staticmethod
    def _get_host_cve_filters(filter_dict):
        """
        Generate filters to filter host's CVEs

        Args:
            filter_dict(dict): filter dict to filter host's CVEs, e.g.
                {
                    "cve_id": "",
                    "severity": ["high", "unknown"],
                    "affected": True,
                    "fixed": False  // The default is false if the field is null.
                }

        Returns:
            set
        """
        fixed = filter_dict.get("fixed", False)
        filters = {CveHostAssociation.fixed == fixed}
        
        if not filter_dict:
            return filters

        if filter_dict.get("cve_id"):
            filters.add(CveHostAssociation.cve_id.like(
                "%" + filter_dict["cve_id"] + "%"))
        if filter_dict.get("severity"):
            filters.add(Cve.severity.in_(filter_dict["severity"]))

        if filter_dict.get("hotpatch") and fixed is True:
            filters.add(CveHostAssociation.fixed_by_hp.in_(filter_dict["hotpatch"]))
        elif filter_dict.get("hotpatch") and fixed is False:
            filters.add(CveHostAssociation.support_hp.in_(filter_dict["hotpatch"]))

        if "affected" in filter_dict:
            filters.add(CveHostAssociation.affected == filter_dict["affected"])
        return filters

    def _query_host_cve(self, username, host_id, filters):
        """
        query needed host CVEs info
        Args:
            username (str): user name of the request
            host_id (int): host id
            filters (set): filter given by user

        Returns:
            sqlalchemy.orm.query.Query
        """
        host_cve_query = self.session.query(CveHostAssociation.cve_id, Cve.publish_time, Cve.severity, Cve.cvss_score,
                                            CveHostAssociation.fixed, CveHostAssociation.support_hp,
                                            CveHostAssociation.fixed_by_hp) \
            .select_from(CveHostAssociation) \
            .outerjoin(Cve, CveHostAssociation.cve_id == Cve.cve_id) \
            .outerjoin(Host, Host.host_id == CveHostAssociation.host_id) \
            .filter(CveHostAssociation.host_id == host_id, Host.user == username) \
            .filter(*filters)

        return host_cve_query

    @staticmethod
    def _host_cve_row2dict(rows, description_dict):
        """
        reformat queried rows to list of dict and add description for each cve
        Args:
            rows:
            description_dict (dict): key is cve's id, value is cve's description

        Returns:
            list
        """
        result = []
        for row in rows:
            cve_id = row.cve_id
            cve_info = {
                "cve_id": cve_id,
                "publish_time": row.publish_time,
                "severity": row.severity,
                "description": description_dict[cve_id] if description_dict.get(cve_id) else "",
                "cvss_score": row.cvss_score,
                "hotpatch": row.fixed_by_hp if row.fixed is True else row.support_hp
            }
            result.append(cve_info)
        return result
