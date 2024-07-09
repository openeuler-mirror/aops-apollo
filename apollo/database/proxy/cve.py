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
import math
from collections import defaultdict
from typing import Tuple

from elasticsearch import ElasticsearchException
from sqlalchemy import func, tuple_, case
from sqlalchemy.exc import SQLAlchemyError

from vulcanus.database.helper import sort_and_page
from vulcanus.database.proxy import MysqlProxy, ElasticsearchProxy
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import DATABASE_INSERT_ERROR, DATABASE_QUERY_ERROR, NO_DATA, SUCCEED

from apollo.database.mapping import CVE_INDEX
from apollo.database.table import Cve, CveHostAssociation, CveAffectedPkgs, AdvisoryDownloadRecord
from apollo.function.customize_exception import EsOperationError


class CveMysqlProxy(MysqlProxy):
    """
    Cve mysql related table operation
    """

    def get_cve_overview(self, host_list):
        """
        Get cve number overview based on severity

        Args:
            host_list(list): list of host id to be counted
        Returns:
            str: status code
            dict: query result. e.g.
                {
                    "Critical": 11,
                    "High": 6,
                    "Medium": 5,
                    "Low": 0,
                    "Unknown": 0
                }

        """
        result = {}
        try:
            result = self._get_processed_cve_overview(host_list)
            LOGGER.debug("Finished getting cve overview.")
            return SUCCEED, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve overview failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_cve_overview(self, host_list):
        """
        get cve overview info from database
        Args:
            data (dict): e.g. {"username": "admin"}

        Returns:
            dict
        """
        result = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        cve_overview = self.session.execute(
            "CALL GET_CVE_OVERVIEW_PRO(:host_list)",
            {"host_list": ','.join([f"'{item}'" for item in host_list]) if host_list else None},
        ).fetchall()

        for severity, count in cve_overview:
            if severity not in result:
                LOGGER.debug("Unknown cve severity '%s' when getting overview." % severity)
                continue
            result[severity] = count
        return result

    def query_host_id_list_related_to_cve(self, cve_id: str, fixed: bool) -> Tuple[str, list]:
        """Query all host IDs related to the target CVE ID.

        Args:
            cve_id (str): The CVE ID to query.
            fixed (bool): Flag indicating whether the CVE is fixed or not.
        Returns:
            Tuple[str, list]: A tuple containing the status code and the list of host IDs.
                - status_code (str): The status code indicating the success or failure of the query.
                - result (list): The list of host IDs associated with the given CVE ID.

        """
        try:
            result = (
                self.session.query(CveHostAssociation.host_id)
                .filter(CveHostAssociation.fixed == fixed, CveHostAssociation.cve_id == cve_id)
                .all()
            )
            LOGGER.debug("Finished getting cve hosts.")
            return SUCCEED, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve hosts failed due to internal error")
            return DATABASE_QUERY_ERROR, []

    def get_cve_task_hosts(self, data):
        """
        get hosts basic info of multiple CVE, also return CVEs' source packages
        Args:
            data (dict): parameter, e.g.
                {
                    "cve_list": [
                        {
                            "cve_id": "CVE-2023-1",
                            "rpms": [{
                                "installed_rpm": "pkg1",
                                "available_rpm": "pkg1-1",
                                "fix_way":"hotpatch"
                            }]
                        },
                        {
                            "cve_id": "CVE-2023-2",
                            "rpms": []
                        }
                    ],
                    "host_list": [id1, id2] // optional param. Only return the filtered host info when fixed is True
                    "fixed": false
                }

        Returns:
            int: status code
            dict: query result. e.g. when 'fixed' in filter dict is False
                {
                    "result": {
                        "CVE-2023-25180": {
                            "package": "glibc",
                            "hosts": [{
                                "host_id": 1100,
                                "host_ip": "172.168.120.151",
                                "host_name": "host2_12006",
                                "hotpatch": True // The param only exist if input fixed is True
                            }]
                        }
                    }
                }
        """
        try:
            query_rows = self._get_processed_cve_task_hosts(data)
            LOGGER.debug("Finished querying cve task hosts.")
            return SUCCEED, query_rows
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve task hosts failed due to internal error.")
            return DATABASE_QUERY_ERROR, []

    def _get_processed_cve_task_hosts(self, data):
        """
        Query and process cve task hosts data
        Args:
            data (dict): query condition

        Returns:
            int: status code
            dict
        """
        fixed_flag = data["fixed"]
        cve_info_list = data["cve_list"]

        cve_id_list = [cve_info["cve_id"] for cve_info in cve_info_list]
        host_list = data.get("host_list", [])
        cve_task_hosts_rows = self._query_cve_task_host_pkg(fixed_flag, cve_id_list, host_list)
        return cve_task_hosts_rows

    def _query_cve_task_host_pkg(self, fixed: bool, cve_list: list, host_list: list):
        """
        query needed cve hosts basic info
        Args:
            fixed (bool): query fixed package or not
            cve_list (list): cve id list
            host_list (list): host id list

        Returns:
            sqlalchemy.orm.query.Query
        """
        filters = {
            CveHostAssociation.fixed == fixed,
            CveHostAssociation.cve_id.in_(cve_list),
            CveHostAssociation.host_id.in_(host_list),
        }
        # when query host to fix, only query the ones which have available rpm to fix
        if not fixed:
            filters.add(CveHostAssociation.available_rpm != None)

        cve_host_list = (
            self.session.query(
                CveHostAssociation.cve_id,
                CveHostAssociation.host_id,
                CveHostAssociation.fixed_way,
                CveHostAssociation.installed_rpm,
                CveHostAssociation.available_rpm,
                CveHostAssociation.cluster_id,
            )
            .filter(*filters)
            .all()
        )
        return cve_host_list

    def _get_cve_source_pkg(self, cve_list: list) -> dict:
        """
        Query cve related source packages
        Args:
            cve_list (list): cve id list

        Returns:
            dict: affected source packages of CVEs.  e.g.
                {"cve-2023-1": "kernel, vim", "cve-2023-2": "kernel", "cve-2023-3": ""}
        """
        cve_pkgs_dict = defaultdict(set)
        result = {}
        cve_package_query = self._query_cve_package(cve_list)

        for row in cve_package_query:
            cve_pkgs_dict[row.cve_id].add(row.package)

        for cve_id, pkg_set in cve_pkgs_dict.items():
            result[cve_id] = ",".join(list(pkg_set))

        succeed_list = [row.cve_id for row in cve_package_query]
        fail_list = list(set(cve_list) - set(succeed_list))
        if fail_list:
            for cve_id in fail_list:
                result[cve_id] = ""
            LOGGER.debug("No data found when getting the source package of cve: %s." % fail_list)

        return result

    def _query_cve_package(self, cve_list):
        """
        query cve affect source packages from database
        Args:
            cve_list (list): cve id list

        Returns:
            sqlalchemy.orm.query.Query

        """
        cve_pkg_query = (
            self.session.query(Cve.cve_id, CveAffectedPkgs.package)
            .join(CveAffectedPkgs, Cve.cve_id == CveAffectedPkgs.cve_id)
            .filter(Cve.cve_id.in_(cve_list))
        )
        return cve_pkg_query


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
                        "search_key ": "cve-2021",
                        "severity": "medium",
                        "affected": True,
                        "fixed": True,
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
                            "package": "kernel,vim",
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
        cve_list, total = self._query_cve_list(data)

        description_dict = self._get_cve_description([cve_info["cve_id"] for cve_info in cve_list])

        result['result'] = self._add_description_to_cve(cve_list, description_dict)
        if total:
            result['total_page'] = math.ceil(total / data.get("per_page", total))
            result['total_count'] = total
        return result

    @staticmethod
    def _sort_and_page_cve_list(data: dict) -> dict:
        """
        Sort and paginate a list of CVEs (Common Vulnerabilities and Exposures).

        Args:
            data (dict): A dictionary containing pagination and sorting information.
                        Keys expected in the dictionary:
                        - 'page' (int, optional): The current page number.
                        - 'per_page' (int, optional): The number of items per page.
                        - 'direction' (str, optional): The sorting direction, either 'asc' or 'desc'.
                        - 'sort' (str, optional): The field to sort by.

        Returns:
            dict: A dictionary containing sorting and pagination details with the following keys:
                - 'start_limt' (int): The starting index for pagination.
                - 'limt_size' (int): The number of items per page.
                - 'order_by' (str): The sorting direction.
                - 'order_by_filed' (str): The field to sort by.
        """
        sort_page = dict(start_limt=0, limt_size=0)
        page, per_page = data.get('page'), data.get('per_page')
        if all((page, per_page)):
            sort_page['start_limt'] = int(per_page) * (int(page) - 1)
            sort_page['limt_size'] = int(per_page)

        # sort by host num by default
        sort_page["order_by"] = data.get("direction", "asc")
        sort_page["order_by_filed"] = data.get('sort', "cve_id")
        if sort_page["order_by_filed"] == "host_num":
            sort_page["order_by_filed"] = f"host_num {sort_page['order_by']},cve_id "

        return sort_page

    def _query_cve_list(self, data):
        """
        query needed cve info
        Args:
            data (set): filter given by user

        Returns:
            sqlalchemy.orm.query.Query: attention, two rows may have same cve id with different source package.
        """
        filters = {
            "search_key": None,
            "affected": True,
            "host_list": ','.join(f"'{item}'" for item in data.get("host_list", [])) or None,
        }
        filters.update(data.get("filter", {}))
        filters.update(self._sort_and_page_cve_list(data))
        if filters.get("severity"):
            filters["severity"] = ",".join(["'" + serverity + "'" for serverity in filters["severity"]])
        else:
            filters["severity"] = None

        # Call stored procedure: GET_CVE_LIST_PRO
        pro_result_set = self.session.execute(
            "CALL GET_CVE_LIST_PRO(:search_key,:severity,:fixed,:affected,:order_by_filed,:order_by,:start_limt,:limt_size,:host_list)",
            filters,
        )
        cursor = pro_result_set.cursor
        columns = [column[0] for column in cursor.description]
        cve_list = [dict(zip(columns, cve)) for cve in cursor.fetchall()]
        cursor.nextset()
        total = cursor.fetchone()[0]
        return cve_list, total

    @staticmethod
    def _add_description_to_cve(cve_info_list, description_dict):
        """
        add description for each cve
        Args:
            cve_info_list: list of cve info without description and package
            description_dict (dict): key is cve's id, value is cve's description

        Returns:
            list
        """
        for cve_info in cve_info_list:
            cve_id = cve_info["cve_id"]
            cve_info["description"] = description_dict[cve_id] if description_dict.get(cve_id) else None
        return cve_info_list

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
        cve_info_data = self._query_cve_info(cve_id)
        if cve_info_data:
            # raise exception when multiple record found

            description_dict = self._get_cve_description([cve_info_data.cve_id])
            pkg_list = self._get_affected_pkgs(cve_id)

            info_dict = self._cve_info_row2dict(cve_info_data, description_dict, pkg_list)
            info_dict["related_cve"] = self._get_related_cve(cve_id, pkg_list)
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

    def _query_cve_info(self, cve_id):
        """
        query needed cve info
        Args:
            cve_id (str): cve id

        Returns:
            sqlalchemy.orm.query.Query
        """
        cve_info = (
            self.session.query(
                case([(Cve.cve_id == None, "")], else_=Cve.cve_id).label("cve_id"),
                case([(Cve.publish_time == None, "")], else_=Cve.publish_time).label("publish_time"),
                case([(Cve.severity == None, "")], else_=Cve.severity).label("severity"),
                case([(Cve.cvss_score == None, "")], else_=Cve.cvss_score).label("cvss_score"),
            )
            .filter(Cve.cve_id == cve_id)
            .first()
        )

        return cve_info

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

    def _get_related_cve(self, cve_id, pkg_list):
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

        exist_cve = (
            self.session.query(CveHostAssociation.cve_id)
            .filter(CveHostAssociation.fixed == 0, CveHostAssociation.affected == 1)
            .distinct()
            .all()
        )
        cve_ids = [cve.cve_id for cve in exist_cve]
        related_cve = (
            self.session.query(CveAffectedPkgs.cve_id)
            .filter(CveAffectedPkgs.package.in_(pkg_list), CveAffectedPkgs.cve_id.in_(cve_ids))
            .distinct()
            .all()
        )

        related_cve = [cve.cve_id for cve in related_cve if cve.cve_id != cve_id]

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
            LOGGER.error("Delete advisory download failed record error.")
            self.session.rollback()

    def save_security_advisory(self, file_name, security_cvrf_info):
        """
        save security advisory to mysql and es
        Args:
            file_name (str): security advisory's name
            security_cvrf_info (SecurityCvrfInfo): {
                cve_rows (list): list of dict to insert to mysql Cve table
                cve_pkg_rows (list): list of dict to insert to mysql CveAffectedPkgs table
                cve_pkg_docs (list): list of dict to insert to es CVE_INDEX
                sa_year(str): security advisory year
                sa_number(str): security advisory order number
            }
        Returns:
            int: status code
        """
        try:
            self._save_security_advisory(security_cvrf_info)
            self.session.commit()
            LOGGER.debug("Finished saving security advisory '%s'." % file_name)
            return SUCCEED
        except (SQLAlchemyError, ElasticsearchException, EsOperationError) as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Saving security advisory '%s' failed due to internal error." % file_name)
            return DATABASE_INSERT_ERROR

    def _save_security_advisory(self, security_cvrf_info):
        """
        save data into mysql and es

        Args:
            security_cvrf_info (SecurityCvrfInfo): {
                cve_rows (list): list of dict to insert to mysql Cve table
                cve_pkg_rows (list): list of dict to insert to mysql CveAffectedPkgs table
                cve_pkg_docs (list): list of dict to insert to es CVE_INDEX
                sa_year(str): security advisory year
                sa_number(str): security advisory order number
            }


        Raises:
            SQLAlchemyError, ElasticsearchException, EsOperationError
        """
        cve_list = [row_dict["cve_id"] for row_dict in security_cvrf_info.cve_rows]
        cve_query = self.session.query(Cve.cve_id).filter(Cve.cve_id.in_(cve_list))
        update_cve_set = {row.cve_id for row in cve_query}

        update_cve_rows = []
        insert_cve_rows = []
        for row in security_cvrf_info.cve_rows:
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
            self._insert_cve_pkg_rows(security_cvrf_info.cve_pkg_rows)
            self._save_cve_docs(security_cvrf_info.cve_pkg_docs)
            if all([security_cvrf_info.sa_year, security_cvrf_info.sa_number]):
                self.save_advisory_download_record(
                    [
                        {
                            "advisory_year": security_cvrf_info.sa_year,
                            "advisory_serial_number": security_cvrf_info.sa_number,
                            "download_status": True,
                        }
                    ]
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

    def query_host_name_and_related_cves(self, host_list: list, username: str):
        """
        query all cve by host_id
        Args:
            host_list(list): host id list which you want to query cve info
            username: username
        Returns:
            str: operation status code
            list: cve info list, e.g.
                [
                    [1, "CVE-XXXX-XXXX", "redis-4.2.5-1", "redis-4.2.5-2", "coldpatch", ""]
                ]

        """
        try:
            filters = {Host.user == username}
            if host_list:
                filters.add(CveHostAssociation.host_id.in_(host_list))
            query_rows = self._query_host_cve_info(filters)

            result = []
            for row in query_rows:
                result.append(
                    [
                        row.host_ip,
                        row.host_name,
                        row.CveHostAssociation.cve_id,
                        row.CveHostAssociation.installed_rpm,
                        row.CveHostAssociation.available_rpm,
                        row.CveHostAssociation.support_way,
                        row.CveHostAssociation.fixed_way,
                    ]
                )

            return SUCCEED, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            return DATABASE_QUERY_ERROR, []

    def _query_host_cve_info(self, filters: set):
        """
        query needed cve info

        Args:
            filters (set): filter given by user

        Returns:
            sqlalchemy.orm.query.Query
        """
        cve_query = (
            self.session.query(CveHostAssociation, Host.host_ip, Host.host_name)
            .join(Host, CveHostAssociation.host_id == Host.host_id)
            .filter(*filters)
            .all()
        )
        return cve_query

    def get_cve_unfixed_packages(self, cve_id, host_ids: list, username: str):
        """
        Get unfixed packages of the cve

        Args:
            cve_id: cve id
            host_ids: host list
            username: user name

        Returns:
            status_code: str
            unfixed_rpms:[
                {
                    "installed_rpm":"kernel-5",
                    "available_rpm":"kernel-6",
                    "support_way": "coldpatch/hotpatch/None",
                    "host_num": 10
                }
            ]
        """
        try:
            status_code, unfixed_rpms = self._get_cve_unfixed_packages(cve_id, host_ids, username)
            if status_code != SUCCEED:
                LOGGER.debug("Description Failed to query unfixed rpm packages of the cve, cve id: %s" % cve_id)

            return status_code, unfixed_rpms
        except SQLAlchemyError as error:
            LOGGER.error(error)
            return DATABASE_QUERY_ERROR, []

    def _get_cve_unfixed_packages(self, cve_id, host_ids, username):
        filters = {
            CveHostAssociation.cve_id == cve_id,
            CveHostAssociation.fixed == False,
            CveHostAssociation.host_user == username,
        }
        if host_ids:
            filters.add(CveHostAssociation.host_id.in_(host_ids))

        cve_unfixed_packages = (
            self.session.query(
                CveHostAssociation.installed_rpm,
                CveHostAssociation.available_rpm,
                CveHostAssociation.support_way,
                func.count(CveHostAssociation.host_id).label("host_num"),
            )
            .filter(*filters)
            .group_by('installed_rpm', 'available_rpm', 'support_way')
            .all()
        )
        if not cve_unfixed_packages:
            return NO_DATA, []

        return SUCCEED, self._cve_unfixed_packages_row2dict(cve_unfixed_packages)

    @staticmethod
    def _cve_unfixed_packages_row2dict(rows):
        """
        Unfixed cve package row data converted to dictionary
        Args:
            rows:

        Returns:
            list
        """
        result = []
        for row in rows:
            unfix_rpm = {
                "installed_rpm": row.installed_rpm,
                "available_rpm": row.available_rpm,
                "support_way": row.support_way,
                "host_num": row.host_num,
            }
            result.append(unfix_rpm)
        return result

    def get_cve_fixed_packages(self, cve_id, host_ids: list, username: str):
        """
        Get fixed packages of the cve

        Args:
            cve_id: cve id
            host_ids: host list
            username: user name

        Returns:
            status_code: str
            fixed_rpms: [
                        {
                            "installed_rpm": "kernel-5",
                            "fixed_way": "coldpatch/hotpatch_accepted/hotpatch_actived/",
                            "host_num": 10
                        }
                    ]
        """
        try:
            status_code, fixed_rpms = self._get_cve_fixed_packages(cve_id, host_ids, username)
            if status_code != SUCCEED:
                LOGGER.debug("Description Failed to query fixed rpm packages of the cve, cve id: %s" % cve_id)

            return status_code, fixed_rpms
        except SQLAlchemyError as error:
            LOGGER.error(error)
            return DATABASE_QUERY_ERROR, []

    def _get_cve_fixed_packages(self, cve_id, host_ids, username):
        filters = {
            CveHostAssociation.cve_id == cve_id,
            CveHostAssociation.fixed == True,
            CveHostAssociation.host_user == username,
        }
        if host_ids:
            filters.add(CveHostAssociation.host_id.in_(host_ids))

        cve_fixed_packages = (
            self.session.query(
                CveHostAssociation.installed_rpm,
                CveHostAssociation.fixed_way,
                CveHostAssociation.hp_status,
                func.count(CveHostAssociation.host_id).label("host_num"),
            )
            .filter(*filters)
            .group_by('installed_rpm', 'fixed_way', "hp_status")
            .all()
        )
        if not cve_fixed_packages:
            return NO_DATA, []

        return SUCCEED, self._cve_fixed_packages_row2dict(cve_fixed_packages)

    @staticmethod
    def _cve_fixed_packages_row2dict(rows):
        """
        Fixed cve package row data converted to dictionary
        Args:
            rows:

        Returns:
            list
        """
        result = []

        for row in rows:
            fixed_rpm = {
                "installed_rpm": row.installed_rpm,
                "fixed_way": row.fixed_way,
                "hp_status": row.hp_status,
                "host_num": row.host_num,
            }
            result.append(fixed_rpm)
        return result

    def get_cve_packages_host(self, data):
        """
        Get cve packages host list

        Args:
            data(dict): Fix the query without passing the available_rpm field, e.g.
                {
                    "direction": "asc",
                    "page": 1,
                    "per_page": 10,
                    "username": "admin",
                    "cve_id": "CVE-2023-0120",
                    "available_rpm": "kernel-4.9-ACC"/null,
                    "installed_rpm": "kernel-4.9",
                    "hp_status": "ACCEPTED/ACTIVED",
                    "fixed": True/False
                }

        Returns:
            str: status code
            dict: query result. e.g.
                {
                    "total_count": 1,
                    "total_page": 1,
                    "result": [
                        {
                            "host_name":"主机1",
                            "host_ip":"127.0.0.1"
                        }
                    ]
                }
        """
        result = {}
        try:
            result = self._get_processed_cve_packages_host(data)
            LOGGER.debug("Finished getting cve package host list.")
            return SUCCEED, result
        except (SQLAlchemyError, ElasticsearchException, EsOperationError) as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve package host list failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_cve_packages_host(self, data):
        result = {"total_count": 0, "total_page": 0, "result": []}
        filters = {
            CveHostAssociation.host_user == data["username"],
            CveHostAssociation.cve_id == data["cve_id"],
            CveHostAssociation.installed_rpm == data["installed_rpm"],
            CveHostAssociation.fixed == data["fixed"],
        }
        if data.get("available_rpm"):
            filters.add(CveHostAssociation.available_rpm == data["available_rpm"])

        if data.get("hp_status"):
            filters.add(CveHostAssociation.hp_status == data["hp_status"])
        cve_package_host_query = self._query_cve_package_host(filters)

        total_count = cve_package_host_query.count()
        if not total_count:
            return result

        direction, page, per_page = data.get('direction'), data.get('page'), data.get('per_page')

        processed_query, total_page = sort_and_page(cve_package_host_query, None, direction, per_page, page)

        result['result'] = self._cve_pacakge_host_row2dict(processed_query)
        result['total_page'] = total_page
        result['total_count'] = total_count

        return result

    def _query_cve_package_host(self, filters):
        host_id_subquery = (
            self.session.query(
                CveHostAssociation.host_id,
            )
            .filter(*filters)
            .group_by(CveHostAssociation.host_id)
            .subquery()
        )
        cve_package_host_query = self.session.query(Host.host_name, Host.host_ip).filter(
            Host.host_id.in_(host_id_subquery)
        )
        return cve_package_host_query

    @staticmethod
    def _cve_pacakge_host_row2dict(rows):
        result = []
        for row in rows:
            host_info = {
                "host_name": row.host_name,
                "host_ip": row.host_ip,
            }
            result.append(host_info)
        return result
