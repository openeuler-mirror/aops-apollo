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
Description: parse unaffected cve xml file, insert into database
"""
from xml.etree import cElementTree as ET
from xml.etree.ElementTree import ParseError

from apollo.conf.constant import CVE_SEVERITY, CVSS_SCORE
from apollo.function.customize_exception import ParseAdvisoryError
from apollo.handler.cve_handler.manager.parse_advisory import etree_to_dict

__all__ = ["parse_unaffected_cve"]

from vulcanus.log.log import LOGGER


def parse_unaffected_cve(xml_path):
    """
    parse the unaffected cve xml file, get the rows and docs for insertion
    Args:
        xml_path (str): cvrf xml file's path

    Returns:
        list: list of dict, each dict is a row for mysql Cve table
        list: list of dict, each dict is a document for es cve package index
        list: list of dict, each dict is a document for es cve description

    Raises:
        KeyError, ParseXmlError, IsADirectoryError
    """
    try:
        tree = ET.parse(xml_path)
    except ParseError:
        raise ParseAdvisoryError("The file may not in a correct xml format.")
    except FileNotFoundError:
        raise ParseAdvisoryError("File not found when parsing the xml.")

    root = tree.getroot()
    xml_dict = etree_to_dict(root)
    try:
        cve_rows, cve_pkg_rows, doc_list = parse_cvrf_dict(xml_dict)
    except (TypeError, KeyError, IndexError) as error:
        LOGGER.error(error)
        raise ParseAdvisoryError("Some error happened when parsing the unaffected xml.")

    return cve_rows, cve_pkg_rows, doc_list


def parse_cvrf_dict(cvrf_dict):
    """
    parse cvrf's dict into mysql cve table rows, and es cve package index.
    Args:
        cvrf_dict (dict): cvrf(Common Vulnerability Reporting Framework) info dict

    Returns:
        list: list of dict, each dict is a row for mysql Cve table
        list: list of dict, each dict is a document for es cve package index
        list: e.g.
            [{'cve_id': 'CVE-2021-43809',
              'description': 'a long description',
              }]

    Raises:
        ParseXmlError
    """
    cve_info_list = cvrf_dict["cvrfdoc"]["Vulnerability"]
    cve_table_rows = []
    cve_pkg_rows = []
    doc_list = []
    for cve_info in cve_info_list:
        product_id = cve_info["ProductStatuses"]["Status"]["ProductID"]
        if isinstance(product_id, list):
            product_id = ','.join(product_id)
        remediation = cve_info["Remediations"]["Remediation"]
        if isinstance(remediation, list):
            remediation = remediation[0]
        cvss_score = cve_info["CVSSScoreSets"]["ScoreSet"]["BaseScore"]
        severity = parse_cve_severity(cvss_score)
        cve_row = {
            "cve_id": cve_info["CVE"],
            "publish_time": remediation["DATE"],
            "severity": severity,
            "cvss_score": cvss_score,
            "reboot": False,
            "affected_os": None,
            "unaffected_os": product_id
        }
        cve_table_rows.append(cve_row)
        cve_pkg_rows.append({
            "cve_id": cve_info["CVE"],
            "package": remediation["Description"]
        })
        description = cve_info["Notes"]["Note"].get("text", "")
        doc_list.append({
            "cve_id": cve_info["CVE"],
            "description": description
        })

    return cve_table_rows, cve_pkg_rows, doc_list


def parse_cve_severity(cve_score: str) -> str:
    """
    base cvss score access level
    Args:
        cvss_score(str): cvss score
    Returns:
        cve severity
    """
    cvss_score = float(cve_score)
    if cvss_score >= CVSS_SCORE.HIGH:
        severity = CVE_SEVERITY.CRITICAL
    elif cvss_score >= CVSS_SCORE.MEDIUM:
        severity = CVE_SEVERITY.HIGH
    elif cvss_score >= CVSS_SCORE.LOW:
        severity = CVE_SEVERITY.MEDIUM
    elif cvss_score > CVSS_SCORE.NONE:
        severity = CVE_SEVERITY.LOW
    else:
        severity = CVE_SEVERITY.NONE
    return severity
