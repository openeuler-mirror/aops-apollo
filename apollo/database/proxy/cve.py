#!/usr/bin/python3  pylint:disable=too-many-lines
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
from collections import defaultdict

from elasticsearch import ElasticsearchException
from sqlalchemy import func, tuple_, case, distinct
from sqlalchemy.exc import SQLAlchemyError
from vulcanus.database.helper import sort_and_page, judge_return_code
from vulcanus.database.proxy import MysqlProxy, ElasticsearchProxy
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import DATABASE_INSERT_ERROR, DATABASE_QUERY_ERROR, NO_DATA, SUCCEED

from apollo.database.mapping import CVE_INDEX
from apollo.database.table import Cve, CveHostAssociation, CveAffectedPkgs, AdvisoryDownloadRecord, Host
from apollo.function.customize_exception import EsOperationError


class CveMysqlProxy(MysqlProxy):
    """
    Cve mysql related table operation
    """

    def get_cve_overview(self, data):
        """
        Get cve number overview based on severity

        Args:
            data(dict): parameter, e.g.
                {
                    "username": "admin",
                }

        Returns:
            int: status code
            dict: query result. e.g.
                {
                    "result": {
                        "Critical": 11,
                        "High": 6,
                        "Medium": 5,
                        "Low": 0,
                        "Unknown": 0
                    }
                }

        """
        result = {}
        try:
            result = self._get_processed_cve_overview(data)
            LOGGER.debug("Finished getting cve overview.")
            return SUCCEED, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve overview failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_cve_overview(self, data):
        """
        get cve overview info from database
        Args:
            data (dict): e.g. {"username": "admin"}

        Returns:
            dict
        """
        result = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        username = data["username"]
        cve_overview_query = self._query_cve_overview(username).all()

        for severity, count in cve_overview_query:
            if severity not in result:
                LOGGER.debug("Unknown cve severity '%s' when getting overview." % severity)
                continue
            result[severity] = count
        return {"result": result}

    def _query_cve_overview(self, username):
        """
        query cve overview
        Args:
            username (str): user name of the request

        Returns:
            sqlalchemy.orm.query.Query
        """
        cve_id_with_severity = (
            self.session.query(
                distinct(CveHostAssociation.cve_id),
                case([(Cve.severity == None, "Unknown")], else_=Cve.severity).label("severity"),
            )
            .select_from(CveHostAssociation)
            .outerjoin(Cve, CveHostAssociation.cve_id == Cve.cve_id)
            .outerjoin(Host, CveHostAssociation.host_id == Host.host_id)
            .filter(CveHostAssociation.affected == 1, CveHostAssociation.fixed == 0, Host.user == username)
            .subquery()
        )
        cve_overview_query = self.session.query(
            cve_id_with_severity.c.severity, func.count(cve_id_with_severity.c.severity)
        ).group_by(cve_id_with_severity.c.severity)
        return cve_overview_query

    def get_cve_host(self, data):
        """
        Get hosts info of a cve

        Args:
            data(dict): parameter, e.g.
                {
                    "cve_id": "cve-2021-11111",
                    "sort": "last_scan",
                    "direction": "asc",
                    "page": 1,
                    "per_page": 10,
                    "username": "admin",
                    "filter": {
                        "host_name": "",
                        "host_group": ["group1"],
                        "repo": ["20.03-update"]
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
                            "last_scan": 11,
                            "hotpatch": true
                        }
                    ]
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_cve_hosts(data)
            LOGGER.debug("Finished getting cve hosts.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve hosts failed due to internal error")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_cve_hosts(self, data):
        """
        Query and process cve hosts data
        Args:
            data (dict): query condition

        Returns:
            int: status code
            dict
        """
        result = {"total_count": 0, "total_page": 1, "result": []}

        cve_id = data["cve_id"]
        filters = self._get_cve_hosts_filters(data.get("filter", {}))
        cve_hosts_query = self._query_cve_hosts(data["username"], cve_id, filters, data.get("filter", {}))

        total_count = cve_hosts_query.count()
        if not total_count:
            LOGGER.debug("No data found when getting the hosts of cve: %s." % cve_id)
            return SUCCEED, result

        sort_column = getattr(Host, data['sort']) if "sort" in data else None
        direction, page, per_page = data.get('direction'), data.get('page'), data.get('per_page')

        processed_query, total_page = sort_and_page(cve_hosts_query, sort_column, direction, per_page, page)
        result['result'] = self._cve_hosts_row2dict(processed_query)
        result['total_page'] = total_page
        result['total_count'] = total_count

        return SUCCEED, result

    @staticmethod
    def _get_cve_hosts_filters(filter_dict):
        """
        Generate filters to filter cve hosts

        Args:
            filter_dict(dict): filter dict to filter cve hosts, e.g.
                {
                    "host_name": "",
                    "host_group": ["group1"],
                    "repo": ["20.03-update"]
                }

        Returns:
            set
        """
        # when fixed does not have a value, the query data is not meaningful
        # the default query is unfixed CVE information
        fixed = filter_dict.get("fixed", False)
        filters = {CveHostAssociation.fixed == fixed}
        if not filter_dict:
            return filters

        if filter_dict.get("host_name"):
            filters.add(Host.host_name.like("%" + filter_dict["host_name"] + "%"))
        if filter_dict.get("host_group"):
            filters.add(Host.host_group_name.in_(filter_dict["host_group"]))
        if filter_dict.get("repo"):
            filters.add(Host.repo_name.in_(filter_dict["repo"]))

        if filter_dict.get("hotpatch") and fixed is True:
            filters.add(CveHostAssociation.fixed_by_hp.in_(filter_dict["hotpatch"]))
        elif filter_dict.get("hotpatch") and fixed is False:
            filters.add(CveHostAssociation.support_hp.in_(filter_dict["hotpatch"]))
        return filters

    def _query_cve_hosts(self, username: str, cve_id: str, filters: set, filter_dict: dict):
        """
        query needed cve hosts info
        Args:
            username (str): user name of the request
            cve_id (str): cve id
            filters (set): filter given by user
            filter_dict {
                "fixed": bool,
                "hotpatch": [true, false],
                "hp_status": [accepted, active]
            }
        Returns:
            sqlalchemy.orm.query.Query
        """
        cve_query = (
            self.session.query(
                Host.host_id,
                Host.host_name,
                Host.host_ip,
                Host.host_group_name,
                Host.repo_name,
                Host.last_scan,
                CveHostAssociation.support_hp,
                CveHostAssociation.fixed,
                CveHostAssociation.fixed_by_hp,
                CveHostAssociation.hp_status,
            )
            .join(CveHostAssociation, Host.host_id == CveHostAssociation.host_id)
            .filter(Host.user == username, CveHostAssociation.cve_id == cve_id)
            .filter(*filters)
        )

        if filter_dict.get("fixed"):
            if filter_dict.get("hotpatch") == [True] and filter_dict.get("hp_status"):
                return cve_query.filter(CveHostAssociation.hp_status.in_(filter_dict["hp_status"]))
            elif len(filter_dict.get("hotpatch")) != 1 and filter_dict.get("hp_status"):
                return cve_query.filter(
                    CveHostAssociation.hp_status.in_(filter_dict["hp_status"]), CveHostAssociation.fixed_by_hp == True
                ).union(cve_query.filter(CveHostAssociation.fixed_by_hp == False))
        return cve_query

    @staticmethod
    def _cve_hosts_row2dict(rows):
        result = []
        for row in rows:
            host_info = {
                "host_id": row.host_id,
                "host_name": row.host_name,
                "host_ip": row.host_ip,
                "host_group": row.host_group_name,
                "repo": row.repo_name,
                "last_scan": row.last_scan,
                "hotpatch": row.fixed_by_hp if row.fixed is True else row.support_hp,
                "hp_status": row.hp_status,
            }
            result.append(host_info)
        return result

    def get_cve_task_hosts(self, data):
        """
        get hosts basic info of multiple CVE
        Args:
            data (dict): parameter, e.g.
                {
                    "cve_list": ["cve-2021-11111", "cve-2021-11112"],
                    "username": "admin",
                    "filter":{
                        "fixed":true
                    }
                }

        Returns:
            int: status code
            dict: query result. e.g.
                {
                    "result": {
                        "cve-2021-11111": [
                            {
                                "host_id": 1,
                                "host_name": "name1",
                                "host_ip": "1.1.1.1"
                            },
                            {
                                "host_id": 2,
                                "host_name": "name2",
                                "host_ip": "1.1.1.2"
                            }
                        ],
                        "cve-2021-11112": [
                            {
                                "host_id": 3,
                                "host_name": "name1",
                                "host_ip": "1.1.1.1"
                            }
                        ]
                    }
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_cve_task_hosts(data)
            LOGGER.debug("Finished querying cve task hosts.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve task hosts failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_cve_task_hosts(self, data):
        """
        Query and process cve task hosts data
        Args:
            data (dict): query condition

        Returns:
            int: status code
            dict
        """
        cve_list = data["cve_list"]
        filters = self._get_cve_task_hosts_filters(data["username"], data.get("filter", {}))
        cve_task_hosts = self._query_cve_task_hosts(filters, cve_list)

        result = defaultdict(list)
        for row in cve_task_hosts:
            host_dict = self._cve_task_hosts_row2dict(row)
            result[row.cve_id].append(host_dict)

        succeed_list = list(result.keys())
        fail_list = list(set(cve_list) - set(succeed_list))

        if fail_list:
            LOGGER.debug("No data found when getting the task hosts of cve: %s." % fail_list)

        status_dict = {"succeed_list": succeed_list, "fail_list": fail_list}
        status_code = judge_return_code(status_dict, NO_DATA)
        return status_code, {"result": dict(result)}

    @staticmethod
    def _get_cve_task_hosts_filters(username: str, filters_dict: dict) -> set:
        """
        Generate filters for cve task hosts

        Args:
            filter_dict(dict): filter dict , e.g.
                {
                    "fixed":true
                }

        Returns:
            set

        """
        return {Host.user == username, CveHostAssociation.fixed == filters_dict.get("fixed", False)}

    def _query_cve_task_hosts(self, filters, cve_list):
        """
        query needed cve hosts basic info
        Args:
            filters (str): filter given by user
            cve_list (list): cve id list

        Returns:
            sqlalchemy.orm.query.Query
        """
        cve_query = (
            self.session.query(
                CveHostAssociation.cve_id,
                Host.host_id,
                Host.host_name,
                Host.host_ip,
                CveHostAssociation.support_hp,
                CveHostAssociation.fixed_by_hp,
                CveHostAssociation.fixed,
            )
            .join(CveHostAssociation, Host.host_id == CveHostAssociation.host_id)
            .filter(CveHostAssociation.cve_id.in_(cve_list))
            .filter(*filters)
        )
        return cve_query

    @staticmethod
    def _cve_task_hosts_row2dict(row):
        host_info = {
            "host_id": row.host_id,
            "host_name": row.host_name,
            "host_ip": row.host_ip,
            "hotpatch": row.support_hp if row.fixed is False else row.fixed_by_hp,
        }
        return host_info

    def get_cve_action(self, data):
        """
        query cve action
        Args:
            data (dict): parameter, e.g.
                {
                    "cve_list": ["cve-2021-11111", "cve-2021-11112"]
                }

        Returns:
            int: status code
            dict: query result. e.g.
                {
                    "result": {
                        "cve-2021-11111": {
                            "reboot": True,
                            "package": "redis"
                        },
                        "cve-2021-11112": {
                            "reboot": False,
                            "package": "tensorflow"
                        },
                    }
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_cve_action(data)
            LOGGER.debug("Finished querying cve action.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve action failed due to internal error.")
            return DATABASE_INSERT_ERROR, result

    def _get_processed_cve_action(self, data):
        """
        Query and process cve action data
        Args:
            data (dict): cve list info

        Returns:
            int: status code of operation
            dict
        """
        cve_list = data["cve_list"]
        result = {}

        cve_action_query = self._query_cve_action(cve_list)

        for row in cve_action_query:
            if row.cve_id not in result:
                result[row.cve_id] = {"reboot": row.reboot, "package": row.package}
            else:
                result[row.cve_id]["package"] += "," + row.package
            package_list = list(set(result[row.cve_id]["package"].split(",")))
            result[row.cve_id]["package"] = ",".join(package_list)

        succeed_list = [row.cve_id for row in cve_action_query]
        fail_list = list(set(cve_list) - set(succeed_list))
        if fail_list:
            for cve_id in fail_list:
                result[cve_id] = {"reboot": False, "package": ""}
            LOGGER.debug("No data found when getting the action of cve: %s." % fail_list)

        return SUCCEED, {"result": result}

    def _query_cve_action(self, cve_list):
        """
        query cve action info from database
        Args:
            cve_list (list): cve id list

        Returns:
            sqlalchemy.orm.query.Query

        """
        cve_action_query = (
            self.session.query(Cve.cve_id, CveAffectedPkgs.package, Cve.reboot)
            .join(CveAffectedPkgs, Cve.cve_id == CveAffectedPkgs.cve_id)
            .filter(Cve.cve_id.in_(cve_list))
        )
        return cve_action_query


class CveEsProxy(ElasticsearchProxy):  # pylint:disable=too-few-public-methods
    """
    Cve elasticsearch database related operation
    """

    def _get_cve_description(self, cve_list):
        """
        description of the cve in list
        Args:
            cve_list (list): cve id list

        Returns:
            dict: cve description dict. e.g.
                {"cve_id1": "a long description"}
        Raises:
            EsOperationError
        """
        query_body = self._general_body()
        query_body['query']['bool']['must'].append({"terms": {"cve_id": cve_list}})

        operation_code, res = self.scan(CVE_INDEX, query_body, source=["cve_id", "description"])

        if not operation_code:
            LOGGER.error(EsOperationError("Query cve description in elasticsearch failed."))
            return {}

        description_dict = {}
        for hit in res:
            cve_id = hit["cve_id"]
            description_dict[cve_id] = hit["description"]
        return description_dict


class CveProxy(CveMysqlProxy, CveEsProxy):
    """
    Cve related database operation
    """

    def __init__(self, host=None, port=None):
        """
        Instance initialization

        Args:
            configuration (Config)
            host(str)
            port(int)
        """
        CveMysqlProxy.__init__(self)
        CveEsProxy.__init__(self, host, port)

    def get_cve_list(self, data):
        """
        Get cve list of a user

        Args:
            data(dict): parameter, e.g.
                {
                    "sort": "cve_id",
                    "direction": "asc",
                    "page": 1,
                    "per_page": 10,
                    "username": "admin",
                    "filter": {
                        "cve_id": "cve-2021",
                        "severity": "medium",
                        "affected": True
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
                            "cve_id": "cve-2021-11111",
                            "publish_time": "2020-03-22",
                            "severity": "medium",
                            "description": "a long description",
                            "cvss_score": "7.2",
                            "host_num": 22,
                        }
                    ]
                }
        """
        result = {}
        try:
            result = self._get_processed_cve_list(data)
            LOGGER.debug("Finished getting cve list.")
            return SUCCEED, result
        except (SQLAlchemyError, ElasticsearchException, EsOperationError) as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve list failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_cve_list(self, data):
        """
        Get sorted, paged and filtered cve list.

        Args:
            data(dict): sort, page and filter info
        Returns:
            dict
        Raises:
            EsOperationError
        """
        result = {"total_count": 0, "total_page": 0, "result": []}

        filters = self._get_cve_list_filters(data.get("filter"), data["username"])
        cve_query = self._query_cve_list(filters)

        total_count = len(cve_query.all())
        if not total_count:
            return result

        sort_column = self._get_cve_list_sort_column(data.get('sort'))
        direction, page, per_page = data.get('direction'), data.get('page'), data.get('per_page')

        processed_query, total_page = sort_and_page(cve_query, sort_column, direction, per_page, page)
        description_dict = self._get_cve_description([row.cve_id for row in processed_query])

        result['result'] = self._cve_list_row2dict(processed_query, description_dict)
        result['total_page'] = total_page
        result['total_count'] = total_count

        return result

    @staticmethod
    def _get_cve_list_sort_column(column_name):
        """
        get column or aggregation column of table by name
        Args:
            column_name (str/None): name of column

        Returns:
            column or aggregation column of table, or None if column name is not given
        """
        if not column_name:
            return None
        if column_name == "host_num":
            return func.count(CveHostAssociation.host_id)
        return getattr(Cve, column_name)

    def _query_cve_list(self, filters):
        """
        query needed cve info
        Args:
            filters (set): filter given by user

        Returns:
            sqlalchemy.orm.query.Query
        """
        cve_query = (
            self.session.query(
                CveHostAssociation.cve_id,
                case([(Cve.publish_time == None, "")], else_=Cve.publish_time).label("publish_time"),
                case([(Cve.severity == None, "")], else_=Cve.severity).label("severity"),
                case([(Cve.cvss_score == None, "")], else_=Cve.cvss_score).label("cvss_score"),
                func.count(CveHostAssociation.host_id).label("host_num"),
            )
            .outerjoin(Cve, CveHostAssociation.cve_id == Cve.cve_id)
            .outerjoin(Host, Host.host_id == CveHostAssociation.host_id)
            .filter(*filters)
            .group_by(CveHostAssociation.cve_id)
        )
        return cve_query

    @staticmethod
    def _cve_list_row2dict(rows, description_dict):
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
                "host_num": row.host_num,
            }
            result.append(cve_info)
        return result

    @staticmethod
    def _get_cve_list_filters(filter_dict, username):
        """
        Generate filters

        Args:
            filter_dict(dict): filter dict to filter cve list, e.g.
                {
                    "cve_id": "2021",
                    "severity": ["high"]
                }
            username(str): admin

        Returns:
            set
        """
        filters = {CveHostAssociation.fixed == filter_dict.get("fixed"), Host.user == username}
        if not filter_dict:
            return filters

        if filter_dict.get("cve_id"):
            filters.add(CveHostAssociation.cve_id.like("%" + filter_dict["cve_id"] + "%"))
        if filter_dict.get("severity"):
            filters.add(Cve.severity.in_(filter_dict["severity"]))
        if "affected" in filter_dict:
            filters.add(CveHostAssociation.affected == filter_dict["affected"])
        return filters

    def get_cve_info(self, data):
        """
        Get cve number overview based on severity

        Args:
            data(dict): parameter, e.g.
                {
                    "cve_id": "cve-2021-11111"
                    "username": "admin",
                }

        Returns:
            int: status code
            dict: query result. e.g.
                {
                    "result": {
                        "cve_id": "cve-2021-11111",
                        "publish_time": "2020-09-24",
                        "severity": "high",
                        "description": "a long description",
                        "cvss_score": "7.2",
                        "package": [{
                                        "package":"apr",
                                        "os_version":"openEuler-22.03-LTS"}]
                        "related_cve": [
                            "cve-2021-11112", "cve-2021-11113"
                        ]
                    }
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_cve_info(data)
            LOGGER.debug("Finished getting cve info.")
            return status_code, result
        except (SQLAlchemyError, ElasticsearchException, EsOperationError) as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve info failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_cve_info(self, data):
        """
        query and process cve info
        Args:
            data (dict): {"cve_id": "cve-2021-11111", "username": "admin"}

        Returns:
            int: status code
            dict: query result

        Raises:
            sqlalchemy.orm.exc.MultipleResultsFound
            EsOperationError
        """
        cve_id = data["cve_id"]
        username = data["username"]

        cve_info_query = self._query_cve_info(username, cve_id)
        cve_info_data = cve_info_query.first()
        if cve_info_data:
            # raise exception when multiple record found

            description_dict = self._get_cve_description([cve_info_data.cve_id])
            pkg_list = self._get_affected_pkgs(cve_id)

            info_dict = self._cve_info_row2dict(cve_info_data, description_dict, pkg_list)
            info_dict["related_cve"] = self._get_related_cve(username, cve_id, pkg_list)
        else:
            info_dict = {
                "cve_id": cve_id,
                "publish_time": "",
                "severity": "",
                "description": "",
                "cvss_score": "",
                "package": [],
                "related_cve": [],
            }
        return SUCCEED, {"result": info_dict}

    def _query_cve_info(self, username, cve_id):
        """
        query needed cve info
        Args:
            username (str): user name of the request
            cve_id (str): cve id

        Returns:
            sqlalchemy.orm.query.Query
        """
        cve_info_query = self.session.query(
            case([(Cve.cve_id == None, "")], else_=Cve.cve_id).label("cve_id"),
            case([(Cve.publish_time == None, "")], else_=Cve.publish_time).label("publish_time"),
            case([(Cve.severity == None, "")], else_=Cve.severity).label("severity"),
            case([(Cve.cvss_score == None, "")], else_=Cve.cvss_score).label("cvss_score"),
        ).filter(Cve.cve_id == cve_id)

        return cve_info_query

    def _get_affected_pkgs(self, cve_id):
        """
        get cve's affected packages
        Args:
            cve_id (str): cve id

        Returns:
            list
        """
        pkg_query = self.session.query(CveAffectedPkgs).filter(
            CveAffectedPkgs.cve_id == cve_id, CveAffectedPkgs.affected == 1
        )
        pkg_list = [{"package": row.package, "os_version": row.os_version} for row in pkg_query]
        return pkg_list

    def _get_related_cve(self, username, cve_id, pkg_list):
        """
        get related CVEs which have same package as the given cve
        Args:
            username (str): username
            cve_id (str): cve id
            pkg_list (list): package name list of the given cve

        Returns:
            list
        """
        # if list is empty, which may happened when CVE's package is
        # not record, return empty list
        if not pkg_list:
            return []
        pkg_list = [pkg["package"] for pkg in pkg_list]

        exist_cve_query = (
            self.session.query(CveHostAssociation.cve_id)
            .join(Host, Host.host_id == CveHostAssociation.host_id)
            .filter(Host.user == username, CveHostAssociation.affected == 1, CveHostAssociation.fixed == 0)
        )

        related_cve_query = (
            self.session.query(CveAffectedPkgs.cve_id)
            .filter(CveAffectedPkgs.package.in_(pkg_list), CveAffectedPkgs.cve_id.in_(exist_cve_query.subquery()))
            .distinct()
        )

        related_cve = [row[0] for row in related_cve_query.all() if row[0] != cve_id]

        return related_cve

    @staticmethod
    def _cve_info_row2dict(row, description_dict, pkg_list):
        """
        reformat queried row to dict and add description for the cve
        Args:
            row:
            description_dict (dict): key is cve's id, value is cve's description
            pkg_list (list): cve's affected packages

        Returns:
            dict
        """
        cve_id = row.cve_id
        cve_info = {
            "cve_id": cve_id,
            "publish_time": row.publish_time,
            "severity": row.severity,
            "description": description_dict[cve_id] if description_dict.get(cve_id) else "",
            "cvss_score": row.cvss_score,
            "package": pkg_list,
            "related_cve": [],
        }
        return cve_info

    def save_unaffected_cve(self, file_name, cve_rows, cve_pkg_rows, doc_list):
        """
        save unaffected cve to mysql and es
        Args:
            file_name (str): unaffected cve's name
            cve_rows (list): list of dict to insert to mysql Cve table
            cve_pkg_rows (list): list of dict to insert to mysql CveAffectedPkgs table
            doc_list (list): list of dict dict is a document for es cve description

        Returns:
            int: status code
        """
        try:
            self._save_unaffected_cve(cve_rows, cve_pkg_rows, doc_list)
            self.session.commit()
            LOGGER.debug("Finished saving unaffected cves' cvrf file '%s'" % file_name)
            return SUCCEED
        except (SQLAlchemyError, ElasticsearchException, EsOperationError) as error:
            LOGGER.error(error)
            LOGGER.error("Saving unaffected cves' cvrf file '%s' failed due to internal error." % file_name)
            return DATABASE_INSERT_ERROR

    def _save_unaffected_cve(self, cve_rows, cve_pkg_rows, doc_list):
        """
        save data into mysql

        Args:
            cve_rows (list): list of dict to insert to mysql Cve table
            cve_pkg_rows (list): list of dict to insert to mysql CveAffectedPkgs table
            doc_list (list): list of dict dict is a document for es cve description

        Raises:
            SQLAlchemyError
        """
        cve_list = [row_dict["cve_id"] for row_dict in cve_rows]
        cve_query = self.session.query(Cve.cve_id).filter(Cve.cve_id.in_(cve_list))
        update_cve_set = {row.cve_id for row in cve_query}

        update_cve_rows = []
        insert_cve_rows = []
        for row in cve_rows:
            if row["cve_id"] in update_cve_set:
                update_cve_rows.append(row)
            else:
                insert_cve_rows.append(row)

        # Cve table need commit after add, otherwise following insertion will fail due to
        # Cve.cve_id foreign key constraint.
        # In some case the cve may already exist and some info may changed like cvss score,
        # here we choose insert + commit then update instead of session.merge(), so that when
        # rolling back due to some error, the updated info can be rolled back
        self.session.bulk_insert_mappings(Cve, insert_cve_rows)
        self.session.commit()
        try:
            self.session.bulk_update_mappings(Cve, update_cve_rows)
            self._insert_cve_pkg_rows(cve_pkg_rows)
            self._save_cve_docs(doc_list)
        except (SQLAlchemyError, ElasticsearchException, EsOperationError):
            self.session.rollback()
            self._delete_cve_rows(insert_cve_rows)
            self.session.commit()
            raise

    def save_advisory_download_record(self, sa_record_rows: list) -> int:
        """
        Save the record of download sa
        Args:
            sa_record_rows(list): each element is a record of the AdvisoryDownloadRecord table,e.g.
                [{"advisory_year": 2022,
                "advisory_serial_number": 1230,
                "download_status": 1}]

        Returns:
            int: status code
        """
        try:
            self.session.bulk_insert_mappings(AdvisoryDownloadRecord, sa_record_rows)
            self.session.commit()
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Insert sa parsed record failed due to internal error.")
            return DATABASE_INSERT_ERROR

    def get_advisory_download_record(self):
        """
        Get records of download successes and failures
        Returns:
            list: each element is download succeeded AdvisoryDownloadRecord object
            list: each element is download failed AdvisoryDownloadRecord object
        """
        download_succeed_record, download_failed_advisory = [], []
        try:
            download_record = self.session.query(AdvisoryDownloadRecord).all()
            for record in download_record:
                if record.download_status:
                    download_succeed_record.append(record)
                else:
                    download_failed_advisory.append(record)
            return download_succeed_record, download_failed_advisory
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Query AdvisoryDownloadRecord failed due to internal error.")
            return [], []

    def delete_advisory_download_failed_record(self, id_list: list):
        """
        When sa download fails, need to delete this download record from the database

        Args:
            id_list: Need to delete the record the id of the list
        """
        try:
            self.session.query(AdvisoryDownloadRecord).filter(AdvisoryDownloadRecord.id.in_(id_list)).delete(
                synchronize_session=False
            )
            self.session.commit()
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("delete advisory download failed record error.")
            self.session.rollback()

    def save_security_advisory(self, file_name, cve_rows, cve_pkg_rows, cve_pkg_docs, sa_year=None, sa_number=None):
        """
        save security advisory to mysql and es
        Args:
            file_name (str): security advisory's name
            cve_rows (list): list of dict to insert to mysql Cve table
            cve_pkg_rows (list): list of dict to insert to mysql CveAffectedPkgs table
            cve_pkg_docs (list): list of dict to insert to es CVE_INDEX
            sa_year(str): security advisory year
            sa_number(str): security advisory order number

        Returns:
            int: status code
        """
        try:
            self._save_security_advisory(cve_rows, cve_pkg_rows, cve_pkg_docs, sa_year, sa_number)
            self.session.commit()
            LOGGER.debug("Finished saving security advisory '%s'." % file_name)
            return SUCCEED
        except (SQLAlchemyError, ElasticsearchException, EsOperationError) as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Saving security advisory '%s' failed due to internal error." % file_name)
            return DATABASE_INSERT_ERROR

    def _save_security_advisory(self, cve_rows, cve_pkg_rows, cve_pkg_docs, sa_year=None, sa_number=None):
        """
        save data into mysql and es

        Args:
            cve_rows (list): list of dict to insert to mysql Cve table
            cve_pkg_rows (list): list of dict to insert to mysql CveAffectedPkgs table
            cve_pkg_docs (list): list of dict to insert to es CVE_INDEX
            sa_year(str): security advisory year
            sa_number(str): security advisory order number

        Raises:
            SQLAlchemyError, ElasticsearchException, EsOperationError
        """
        cve_list = [row_dict["cve_id"] for row_dict in cve_rows]
        cve_query = self.session.query(Cve.cve_id).filter(Cve.cve_id.in_(cve_list))
        update_cve_set = {row.cve_id for row in cve_query}

        update_cve_rows = []
        insert_cve_rows = []
        for row in cve_rows:
            if row["cve_id"] in update_cve_set:
                update_cve_rows.append(row)
            else:
                insert_cve_rows.append(row)

        # Cve table need commit after add, otherwise following insertion will fail due to
        # Cve.cve_id foreign key constraint.
        # In some case the cve may already exist and some info may changed like cvss score,
        # here we choose insert + commit then update instead of session.merge(), so that when
        # rolling back due to some error, the updated info can be rolled back
        self.session.bulk_insert_mappings(Cve, insert_cve_rows)
        self.session.commit()
        try:
            self.session.bulk_update_mappings(Cve, update_cve_rows)
            self._insert_cve_pkg_rows(cve_pkg_rows)
            self._save_cve_docs(cve_pkg_docs)
            if all([sa_year, sa_number]):
                self.save_advisory_download_record(
                    [{"advisory_year": sa_year, "advisory_serial_number": sa_number, "download_status": True}]
                )
        except (SQLAlchemyError, ElasticsearchException, EsOperationError):
            self.session.rollback()
            self._delete_cve_rows(insert_cve_rows)
            self.session.commit()
            raise

    def _insert_cve_pkg_rows(self, cve_pkg_rows):
        """
        insert rows into mysql CveAffectedPkgs table. Ignore the rows which already exist

        Args:
            cve_pkg_rows (list): list of row dict. e.g.
                [{
                    "cve_id": "cve-2021-1001",
                     "package": "redis",
                     "package_version": "1.2",
                     "os_version": "openEuler-22.03-LTS",
                     "affected": 1
                }]
        """
        # get the tuples of cve_id and package name
        cve_pkg_keys = [
            (row["cve_id"], row["package"], row["package_version"], row["os_version"]) for row in cve_pkg_rows
        ]

        # delete the exist records first then insert the rows
        self.session.query(CveAffectedPkgs).filter(
            tuple_(
                CveAffectedPkgs.cve_id,
                CveAffectedPkgs.package,
                CveAffectedPkgs.package_version,
                CveAffectedPkgs.os_version,
            ).in_(cve_pkg_keys)
        ).delete(synchronize_session=False)
        self.session.bulk_insert_mappings(CveAffectedPkgs, cve_pkg_rows)

    def _save_cve_docs(self, cve_pkg_docs):
        """
        insert docs into es CVE_INDEX, document id is cve's id
        if the cve already exist, update the description
        Args:
            cve_pkg_docs (list):
                [{'cve_id': 'CVE-2021-43809',
                  'description': 'a long description'}]
        Raises:
            EsOperationError
        """
        cve_list = [doc["cve_id"] for doc in cve_pkg_docs]
        exist_docs = self._get_exist_cve_docs(cve_list)
        exist_cve_set = {doc["cve_id"] for doc in exist_docs}
        update_docs = []
        insert_docs = []

        for doc in cve_pkg_docs:
            if doc["cve_id"] in exist_cve_set:
                update_docs.append(doc)
            else:
                insert_docs.append(doc)

        # elasticsearch need 1 second to update doc
        self._insert_cve_docs(insert_docs)
        try:
            self._update_cve_docs(exist_docs, update_docs)
        except EsOperationError:
            insert_cve_list = [doc["cve_id"] for doc in insert_docs]
            self._delete_cve_docs(insert_cve_list)
            raise

    def _get_exist_cve_docs(self, cve_list):
        """
        query exist cve package doc from elasticsearch
        Args:
            cve_list (list): cve id list

        Returns:
            list: list of cve's pkg info doc

        Raises:
            EsOperationError
        """
        query_body = self._general_body()
        query_body['query']['bool']['must'].append({"terms": {"_id": cve_list}})
        operation_code, res = self.query(CVE_INDEX, query_body, source=True)

        if not operation_code:
            raise EsOperationError("Query exist cve in elasticsearch failed.")

        docs = [hit["_source"] for hit in res["hits"]["hits"]]
        return docs

    def _insert_cve_docs(self, cve_pkg_docs):
        """
        insert new cve info into es CVE_INDEX
        Args:
            cve_pkg_docs (list): list of doc dict

        Raises:
            EsOperationError
        """
        action = []
        for item in cve_pkg_docs:
            action.append({"_index": CVE_INDEX, "_source": item, "_id": item["cve_id"]})

        res = self._bulk(action)
        if not res:
            raise EsOperationError("Insert docs into elasticsearch failed.")

    def _update_cve_docs(self, exist_docs, update_docs):
        """
        update cve's package info in es CVE_INDEX
        Args:
            exist_docs (list): the doc already exist in es
            update_docs (list): the doc to be updated to es

        Raises:
            EsOperationError
        """

        def reformat_doc_list(doc_list):
            doc_dict = {}
            for doc in doc_list:
                doc_dict[doc["cve_id"]] = doc
            return doc_dict

        try:
            exist_docs_dict = reformat_doc_list(exist_docs)
            action = []
            for update_doc in update_docs:
                cve_id = update_doc["cve_id"]
                exist_doc = exist_docs_dict[cve_id]
                update_doc = self._update_cve_doc(exist_doc, update_doc)
                action.append({"_id": cve_id, "_source": update_doc, "_index": CVE_INDEX})
        except (KeyError, TypeError) as error:
            raise EsOperationError("Update docs into elasticsearch failed when process data, %s." % error) from error

        bulk_update_res = self._bulk(action)
        if not bulk_update_res:
            raise EsOperationError("Update docs into elasticsearch failed.")

    @staticmethod
    def _update_cve_doc(old_doc, new_doc):
        """
        update old cve's description
        doc format:
            {
                'cve_id': 'CVE-2021-43809',
                'description': 'a long description'
            }
        Args:
            old_doc (dict): exist doc
            new_doc (dict): update doc

        Returns:
            dict: update doc
        """

        old_doc["description"] = new_doc["description"]
        return old_doc

    def _delete_cve_docs(self, cve_list):
        """
        delete inserted docs to rollback
        Args:
            cve_list (list): the cve list to be delete

        """
        if not cve_list:
            return

        delete_body = self._general_body()
        delete_body["query"]["bool"]["must"].append({"terms": {"_id": cve_list}})
        status = self.delete(CVE_INDEX, delete_body)
        if not status:
            LOGGER.error(
                "Roll back advisory insertion in es failed due to es error, record of "
                "cve '%s' remain in es." % cve_list
            )
            return
        LOGGER.debug("Roll back advisory insertion in es succeed.")

    def _delete_cve_rows(self, insert_cve_rows):
        """
        delete inserted cve table rows
        Args:
            insert_cve_rows (list): cve row dict list

        """
        insert_cve_list = [row["cve_id"] for row in insert_cve_rows]
        self.session.query(Cve).filter(Cve.cve_id.in_(insert_cve_list)).delete(synchronize_session=False)

    def query_host_name_and_related_cves(self, host_id, username):
        """
        query all cve by host_id
        Args:
            host_id: host's id
            username: username
        Returns:
            str:host name
            list: cve list, each element is cve id and status, e.g.
                [
                    ["CVE-2022-12343","affected"]
                ]

        """

        cve_query = (
            self.session.query(CveHostAssociation)
            .join(Host, CveHostAssociation.host_id == Host.host_id)
            .filter(CveHostAssociation.host_id == host_id, Host.user == username)
            .all()
        )
        cve_list = []
        for cve in cve_query:
            cve_list.append(
                [
                    cve.cve_id,
                    "affected" if cve.affected else "affected",
                    "fixed" if cve.fixed else "unfixed",
                    "-" if cve.support_hp is None else "是" if cve.support_hp else "否",
                    "-" if cve.fixed_by_hp is None else "是" if cve.fixed_by_hp else "否",
                ]
            )

        host_info_query = self.session.query(Host).filter(Host.host_id == host_id, Host.user == username).all()
        if host_info_query:
            host_info = host_info_query[0]
            return host_info.host_name, cve_list
        LOGGER.error(f"{host_id} not found in database")
        return "", cve_query
