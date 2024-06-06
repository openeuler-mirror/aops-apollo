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

from typing import List

from sqlalchemy import case, func, or_
from sqlalchemy.exc import SQLAlchemyError
from vulcanus.database.helper import sort_and_page
from vulcanus.database.proxy import MysqlProxy
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import DATABASE_QUERY_ERROR, SUCCEED

from apollo.database.proxy.cve import CveEsProxy
from apollo.database.table import Cve, CveHostAssociation, CveAffectedPkgs


class HostProxy(MysqlProxy, CveEsProxy):
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
        MysqlProxy.__init__(self)
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
        result = {"total_count": 0, "total_page": 0, "result": []}

        host_id = data["host_id"]
        host_cve_query = self._query_host_cve(host_id, data.get("filter", {}))

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

    def _query_host_cve(self, host_id: str, filters_dict: dict):
        """
        query needed host CVEs info
        Args:
            host_id (str): host id
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
            .filter(CveHostAssociation.host_id == host_id)
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

    def query_host_cve_info(self, host_id: str):
        """
        Query CVE information for a specific host.

        Args:
            host_id (str): The ID of the host to query.

        Returns:
            Tuple[str, dict]: A tuple containing the status code and the host's CVE information.
                - Status code (str):
                    - SUCCEED: The query was successful.
                    - DATABASE_QUERY_ERROR: Failed to query the CVE information.
                - Host CVE information (dict): A dictionary containing the CVE information of the host.
        """
        try:
            query_rows = self._query_processed_host_cve_info(host_id)
            host_cve_info = self._host_cve_info_rows_to_dict(query_rows)
            return SUCCEED, host_cve_info
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error(f"Failed to query the CVE information of host ID {host_id}.")
            return DATABASE_QUERY_ERROR, []

    def _query_processed_host_cve_info(self, host_id: str):
        """
        Query host CVE information

        Args:
            host_id(str)

        Returns:
            sqlalchemy.orm.query.Query
        """
        query_rows = (
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
            .filter(
                CveHostAssociation.affected == True,
                CveHostAssociation.fixed == False,
                CveHostAssociation.host_id == host_id,
            )
            .all()
        )
        return query_rows

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
                    "cve_id": row.cve_id,
                    "cvss_score": row.cvss_score,
                    "severity": row.severity,
                    "installed_rpm": row.installed_rpm,
                    "source_package": {row.package},
                    "available_rpms": {row.available_rpm},
                    "support_ways": {row.support_way},
                }

        return list(result.values())
