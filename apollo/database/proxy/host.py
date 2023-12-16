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

from typing import List, Tuple
from sqlalchemy import and_, case, func, or_
from sqlalchemy.exc import SQLAlchemyError
from vulcanus.database.helper import sort_and_page, judge_return_code
from vulcanus.database.proxy import MysqlProxy
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import NO_DATA, DATABASE_QUERY_ERROR, SUCCEED

from apollo.database.proxy.cve import CveEsProxy
from apollo.database.table import Cve, CveHostAssociation, Host, CveAffectedPkgs


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
        result = {"total_count": 0, "total_page": 1, "result": []}

        filters = self._get_host_list_filters(data.get("filter"), data.get("username"))
        host_query = self._query_host_list(filters)

        total_count = host_query.count()
        if not total_count:
            return result

        sort_column = self._get_host_list_sort_column(data.get('sort'))
        direction, page, per_page = data.get('direction'), data.get('page'), data.get('per_page')

        processed_query, total_page = sort_and_page(host_query, sort_column, direction, per_page, page)

        host_rows = processed_query.all()
        host_ids = [host.host_id for host in host_rows]
        host_cve_fixed_info = self._get_host_cve_fixed_info(host_ids)
        result['result'] = self._host_list_row2dict(host_rows, host_cve_fixed_info)
        result['total_page'] = total_page
        result['total_count'] = total_count

        return result

    def _get_host_cve_fixed_info(self, host_ids):
        """
        Get host cve fixed info
        Args:
            host_ids(list): host id list

        Returns:
            dict
        """
        subquery = (
            self.session.query(
                CveHostAssociation.host_id,
                CveHostAssociation.cve_id,
                CveHostAssociation.fixed,
                CveHostAssociation.affected,
            )
            .filter(CveHostAssociation.host_id.in_(host_ids))
            .distinct()
            .subquery()
        )

        host_cve_fixed_list = (
            self.session.query(
                subquery.c.host_id,
                func.COUNT(func.IF(subquery.c.fixed == True, 1, None)).label("fixed_cve_num"),
                func.COUNT(func.IF(subquery.c.fixed == False, 1, None)).label("unfixed_cve_num"),
            )
            .group_by(subquery.c.host_id)
            .all()
        )
        return host_cve_fixed_list

    @staticmethod
    def _get_host_list_sort_column(column_name):
        """
        get column or aggregation column of table by name
        Args:
            column_name (str/None): name of column

        Returns:
            column or aggregation column of table, or None if column name is not given
        """
        if not column_name:
            return None
        return getattr(Host, column_name)

    def _query_host_list(self, filters):
        """
        query needed host info, regardless the host has cve or not
        Args:
            filters (set): filter given by user

        Returns:
            sqlalchemy.orm.query.Query
        """
        query = (
            self.session.query(
                Host.host_id,
                Host.host_name,
                Host.host_ip,
                Host.host_group_name,
                Host.repo_name,
                Host.last_scan,
            )
            .group_by(Host.host_id)
            .filter(*filters)
        )

        return query

    @staticmethod
    def _host_list_row2dict(rows, host_cve_fixed_info):
        result = []
        host_cve_fixed_info_dict = {host_cve.host_id: host_cve for host_cve in host_cve_fixed_info}
        for row in rows:
            unfixed_cve_num, fixed_cve_num = 0, 0
            if row.host_id in host_cve_fixed_info_dict:
                unfixed_cve_num = host_cve_fixed_info_dict[row.host_id].unfixed_cve_num
                fixed_cve_num = host_cve_fixed_info_dict[row.host_id].fixed_cve_num
            host_info = {
                "host_id": row.host_id,
                "host_name": row.host_name,
                "host_ip": row.host_ip,
                "host_group": row.host_group_name,
                "repo": row.repo_name,
                "unfixed_cve_num": unfixed_cve_num,
                "fixed_cve_num": fixed_cve_num,
                "last_scan": row.last_scan,
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
            filters.add(Host.host_name.like("%" + filter_dict["host_name"] + "%"))
        if filter_dict.get("host_group"):
            filters.add(Host.host_group_name.in_(filter_dict["host_group"]))
        if filter_dict.get("repo"):
            repos = [repo if repo else None for repo in filter_dict["repo"]]
            if None in repos:
                filters.add(or_(Host.repo_name.is_(None), Host.repo_name.in_(repos)))
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
            LOGGER.debug("No data found when getting the status of host: %s." % fail_list)

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

        hosts_status_query = self.session.query(Host.host_id, Host.status).filter(*filters)
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
            LOGGER.debug("No data found when getting the info of host: %s." % host_id)
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
        subquery = (
            self.session.query(
                CveHostAssociation.host_id,
                CveHostAssociation.fixed,
                CveHostAssociation.affected,
                CveHostAssociation.cve_id,
            )
            .filter(CveHostAssociation.host_id == host_id)
            .distinct()
            .subquery()
        )
        query = (
            self.session.query(
                Host.host_id,
                Host.host_name,
                Host.host_ip,
                Host.host_group_name,
                Host.repo_name,
                Host.last_scan,
                func.COUNT(func.IF(subquery.c.fixed == True, 1, None)).label("fixed_cve_num"),
                func.COUNT(func.IF(and_(subquery.c.fixed == False, subquery.c.affected == True), 1, None)).label(
                    "affected_cve_num"
                ),
                func.COUNT(func.IF(and_(subquery.c.fixed == False, subquery.c.affected == False), 1, None)).label(
                    "unaffected_cve_num"
                ),
            )
            .outerjoin(subquery, Host.host_id == subquery.c.host_id)
            .group_by(Host.host_id)
            .filter(Host.user == username, Host.host_id == host_id)
        )
        return query

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
            "fixed_cve_num": row.fixed_cve_num,
        }
        return host_info


class HostProxy(HostMysqlProxy, CveEsProxy):
    """
    Host related database operation
    """

    def __init__(self, host=None, port=None):
        """
        Instance initialization

        Args:
            configuration (Config)
            host(str)
            port(int)
        """
        HostMysqlProxy.__init__(self)
        CveEsProxy.__init__(self, host, port)

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
                        "search_key": "",
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
                            "cvss_score": "7.2"
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
        result = {"total_count": 0, "total_page": 1, "result": []}

        host_id = data["host_id"]
        host_cve_query = self._query_host_cve(data["username"], host_id, data.get("filter", {}))

        total_count = host_cve_query.count()
        if not total_count:
            return SUCCEED, result

        sort_column = data['sort'] if "sort" in data else "cve_id"
        direction, page, per_page = data.get('direction'), data.get('page'), data.get('per_page')

        host_cve_list, total_page = sort_and_page(host_cve_query, sort_column, direction, per_page, page)

        cve_id_list = [cve.cve_id for cve in host_cve_list]
        description_dict = self._get_cve_description(cve_id_list)
        result['result'] = self._add_additional_info_to_cve_list(host_cve_list, description_dict)
        result['total_page'] = total_page
        result['total_count'] = total_count

        return SUCCEED, result

    @staticmethod
    def _get_host_cve_filters(filter_dict, cve_affected_pkg_subquery):
        """
        Generate filters to filter host's CVEs

        Args:
            filter_dict(dict): filter dict to filter host's CVEs, e.g.
                {
                    "cve_id": "",
                    "severity": ["high", "unknown"],
                    "affected": True,
                    "package": "vim",
                    "fixed": False  // The default is false if the field is null.
                }

        Returns:
            set
        """
        # when fixed does not have a value, the query data is not meaningful
        # the default query is unfixed CVE information
        filters = {CveHostAssociation.fixed == filter_dict.get("fixed", False)}

        if not filter_dict:
            return filters

        if filter_dict.get("search_key"):
            filters.add(
                or_(
                    CveHostAssociation.cve_id.like("%" + filter_dict["search_key"] + "%"),
                    cve_affected_pkg_subquery.c.package.like("%" + filter_dict["search_key"] + "%"),
                )
            )
        if filter_dict.get("severity"):
            filters.add(Cve.severity.in_(filter_dict["severity"]))

        if "affected" in filter_dict:
            filters.add(CveHostAssociation.affected == filter_dict["affected"])
        return filters

    def _query_host_cve(self, username: str, host_id: int, filters_dict: dict):
        """
        query needed host CVEs info
        Args:
            username (str): user name of the request
            host_id (int): host id
            filter_dict(dict): filter dict to filter host's CVEs, e.g.
                {
                    "cve_id": "",
                    "severity": ["high", "unknown"],
                    "affected": True,
                    "package": "vim",
                    "fixed": False  // The default is false if the field is null.
                }
        Returns:
            sqlalchemy.orm.query.Query
        """
        cve_affected_pkg_subquery = (
            self.session.query(
                CveAffectedPkgs.cve_id,
                func.group_concat(func.distinct(CveAffectedPkgs.package), SEPARATOR=",").label("package"),
            )
            .group_by(CveAffectedPkgs.cve_id)
            .distinct()
            .subquery()
        )

        filters = self._get_host_cve_filters(filters_dict, cve_affected_pkg_subquery)

        host_cve_query = (
            self.session.query(
                CveHostAssociation.cve_id,
                case([(Cve.publish_time == None, "")], else_=Cve.publish_time).label("publish_time"),
                case([(Cve.severity == None, "")], else_=Cve.severity).label("severity"),
                case([(Cve.cvss_score == None, "")], else_=Cve.cvss_score).label("cvss_score"),
                case(
                    [(cve_affected_pkg_subquery.c.package == None, "")], else_=cve_affected_pkg_subquery.c.package
                ).label("package"),
            )
            .select_from(CveHostAssociation)
            .outerjoin(Cve, CveHostAssociation.cve_id == Cve.cve_id)
            .outerjoin(cve_affected_pkg_subquery, cve_affected_pkg_subquery.c.cve_id == CveHostAssociation.cve_id)
            .outerjoin(Host, Host.host_id == CveHostAssociation.host_id)
            .filter(CveHostAssociation.host_id == host_id, Host.user == username)
            .filter(*filters)
        ).group_by(CveHostAssociation.cve_id, cve_affected_pkg_subquery.c.package)

        return host_cve_query

    @staticmethod
    def _add_additional_info_to_cve_list(host_cve_list: list, description_dict: dict) -> list:
        """
        add description and affected source packages for each cve

        Args:
            host_cve_list:
            description_dict (dict): key is cve's id, value is cve's description

        Returns:
            list
        """
        host_cve_info_list = []
        for host_cve in host_cve_list:
            description = description_dict[host_cve.cve_id] if description_dict.get(host_cve.cve_id) else ""
            host_cve_info_list.append(
                {
                    "cve_id": host_cve.cve_id,
                    "publish_time": host_cve.publish_time,
                    "severity": host_cve.severity,
                    "cvss_score": host_cve.cvss_score,
                    "package": host_cve.package,
                    "description": description,
                }
            )

        return host_cve_info_list

    def get_user_host_info(self, username, host_list):
        """
        Query host info according to host id list.

        Args:
            username (str): user name
            host_list (list): host id list, can be empty

        Returns:
            list: host info, e.g.
                [
                    {
                        "host_id": 1,
                        "host_ip": "",
                        "host_name": "",
                        "status": ""
                    }
                ]
        """
        result = []
        try:
            result = self._get_host_info(username, host_list)
            LOGGER.debug("Finished getting host info.")
            return result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting host info failed due to internal error.")
            return result

    def _get_host_info(self, username, host_list):
        """
        get info of the host id in host_list. If host list is empty, query all hosts
        """
        filters = {Host.user == username}
        if host_list:
            filters.add(Host.host_id.in_(host_list))

        info_query = self.session.query(Host.host_id, Host.host_name, Host.host_ip, Host.status).filter(*filters)

        info_list = []
        for row in info_query:
            host_info = {
                "host_id": row.host_id,
                "host_name": row.host_name,
                "host_ip": row.host_ip,
                "status": row.status,
            }
            info_list.append(host_info)
        return info_list

    def query_host_cve_info(self, username: str) -> Tuple[str, list]:
        """
        query cve info with host info from database

        Args:
            username (str)

        Returns:
            Tuple[str, list]
            a tuple containing two elements (status code, host with its cve info list).
        """
        try:
            host_cve_info_list = self._quer_processed_host_cve_info(username)
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("update task_cve_host table status failed.")
            return DATABASE_QUERY_ERROR, []

        return SUCCEED, host_cve_info_list

    def _quer_processed_host_cve_info(self, username: str) -> List[dict]:
        """
        query and process host with its cve info

        Args:
            username(str)

        Returns:
            list: host cve info list. e.g
                [{
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
                }]
        """
        subquery = (
            self.session.query(
                CveHostAssociation.host_id,
                CveHostAssociation.cve_id,
                CveHostAssociation.installed_rpm,
                CveHostAssociation.available_rpm,
                CveHostAssociation.support_way,
                case([(Cve.cvss_score == None, "-")], else_=Cve.cvss_score).label("cvss_score"),
                case([(Cve.severity == None, "-")], else_=Cve.severity).label("severity"),
                case([(CveAffectedPkgs.package == None, "-")], else_=CveAffectedPkgs.package).label("package"),
            )
            .outerjoin(Cve, Cve.cve_id == CveHostAssociation.cve_id)
            .outerjoin(CveAffectedPkgs, CveAffectedPkgs.cve_id == CveHostAssociation.cve_id)
            .filter(CveHostAssociation.affected == True, CveHostAssociation.fixed == False)
            .subquery()
        )

        query_rows = (
            self.session.query(
                Host.host_ip,
                Host.host_name,
                subquery.c.host_id,
                subquery.c.cve_id,
                subquery.c.installed_rpm,
                func.ifnull(subquery.c.available_rpm, "-").label("available_rpm"),
                func.ifnull(subquery.c.support_way, "-").label("support_way"),
                subquery.c.cvss_score,
                subquery.c.severity,
                func.ifnull(subquery.c.package, "-").label("package"),
            )
            .outerjoin(subquery, Host.host_id == subquery.c.host_id)
            .filter(Host.user == username)
            .all()
        )

        host_cve_info = self._host_cve_info_rows_to_dict(query_rows)
        return host_cve_info

    @staticmethod
    def _host_cve_info_rows_to_dict(rows: list) -> List[dict]:
        """
        turn query rows to dict

        Args:
            rows(list): sqlalchemy query result list

        Returns:
            list
        """
        result = dict()

        for row in rows:
            key = f"{row.host_id}-{row.cve_id}-{row.installed_rpm}"

            if key in result:
                result[key]["available_rpms"].add(row.available_rpm)
                result[key]["support_ways"].add(row.support_way)
                result[key]["source_package"].add(row.package)
            else:
                result[key] = {
                    "host_id": row.host_id,
                    "host_ip": row.host_ip,
                    "host_name": row.host_name,
                    "cve_id": row.cve_id,
                    "cvss_score": row.cvss_score,
                    "severity": row.severity,
                    "installed_rpm": row.installed_rpm,
                    "source_package": {row.package},
                    "available_rpms": {row.available_rpm},
                    "support_ways": {row.support_way},
                }

        return list(result.values())
