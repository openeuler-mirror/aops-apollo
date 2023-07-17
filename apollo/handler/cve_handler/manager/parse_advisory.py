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
Description: parse security advisory xml file, insert into database
"""
from collections import defaultdict
from xml.etree import cElementTree as ET
from xml.etree.ElementTree import ParseError

from vulcanus.log.log import LOGGER

from apollo.function.customize_exception import ParseAdvisoryError
from apollo.handler.cve_handler.manager.srcpackage_whitelist import SRC_PACKAGES_WHITE_LIST

__all__ = ["parse_security_advisory"]


def parse_security_advisory(xml_path):
    """
    parse the security advisory xml file, get the rows and docs for insertion
    Args:
        xml_path (str): cvrf xml file's path

    Returns:
        list: list of dict, each dict is a row for mysql Cve table
        list: list of dict, each dict is a row for mysql CveAffectedPkgs table
        list: list of dict, each dict is a document for es cve package index

    Raises:
        KeyError, ParseXmlError, IsADirectoryError
    """
    try:
        tree = ET.parse(xml_path)
    except ParseError:
        raise ParseAdvisoryError("The advisory may not in a correct xml format.")
    except FileNotFoundError:
        raise ParseAdvisoryError("File not found when parsing the xml.")

    root = tree.getroot()
    xml_dict = etree_to_dict(root)
    cve_rows, cve_pkg_rows, cve_pkg_docs, sa_year, sa_number = parse_cvrf_dict(xml_dict)
    return cve_rows, cve_pkg_rows, cve_pkg_docs, sa_year, sa_number


def etree_to_dict(node):
    """
    parse the cvrf xml str to dict. openEuler is supported, other OS has not been tested yet.
    Args:
        node (xml.etree.ElementTree.Element): xml ElementTree's node

    Returns:
        dict
    """
    node_name = node.tag.split("}")[1]
    node_dict = {node_name: {} if node.attrib else None}

    children = list(node)
    if children:
        dd = defaultdict(list)
        for dc in map(etree_to_dict, children):
            for k, v in dc.items():
                dd[k].append(v)
        node_dict = {node_name: {k: v[0] if len(v) == 1 else v for k, v in dd.items()}}
    # add node's attribute into node's dict
    if node.attrib:
        node_dict[node_name].update((k, v) for k, v in node.attrib.items())
    if node.text:
        text = node.text.strip()
        if children or node.attrib:
            if text:
                node_dict[node_name]['text'] = text
        else:
            node_dict[node_name] = text
    return node_dict


def parse_cvrf_dict(cvrf_dict):
    """
    parse cvrf's dict into mysql cve table rows, and es cve package index.
    Args:
        cvrf_dict (dict): cvrf(Common Vulnerability Reporting Framework) info dict

    Returns:
        list: list of dict, each dict is a row for mysql Cve table
        list: list of dict, each dict is a row for mysql CveAffectedPkgs table
        list: list of dict, each dict is a document for es cve package index
        str: sa year
        str: sa number

    Raises:
        ParseXmlError
    """
    # affected package of this security advisory. joined with ',' if have multiple packages
    cve_document_notes = cvrf_dict["cvrfdoc"].get("DocumentNotes", "")
    cve_document_tracking = cvrf_dict["cvrfdoc"].get("DocumentTracking", "")
    if not all([cve_document_notes, cve_document_tracking]):
        return [], [], [], "", ""

    cve_info_list = cvrf_dict["cvrfdoc"]["Vulnerability"]
    cvrf_sa = cve_document_tracking["Identification"]["ID"]
    sa_year, sa_number = cvrf_sa.split("-")[2:]

    cvrf_note = cve_document_notes["Note"]
    srcpackage_list = []
    for info in cvrf_note:
        if info["Title"] == "Affected Component":
            srcpackage_list = info["text"].split(",")
            break
    srcpackage_list = [
        SRC_PACKAGES_WHITE_LIST[package] if package in SRC_PACKAGES_WHITE_LIST else package
        for package in srcpackage_list
    ]
    if isinstance(cve_info_list, dict):
        cve_info_list = [cve_info_list]

    package_info_list = cvrf_dict["cvrfdoc"].get("ProductTree", "").get("Branch")

    try:
        cve_table_rows, cve_pkg_rows, cve_description = parse_cve_info(
            cve_info_list, srcpackage_list, package_info_list
        )
        es_cve_pkg_docs = parse_arch_info(cve_description)
    except (KeyError, TypeError, ParseAdvisoryError) as error:
        LOGGER.error(error)
        raise ParseAdvisoryError("Some error happened when parsing the advisory xml.")
    return cve_table_rows, cve_pkg_rows, es_cve_pkg_docs, sa_year, sa_number


def parse_cve_info(cve_info_list, srcpackage_list, package_info_list):
    """
    get mysql Cve and CveAffectedPkgs table rows, and description info for elasticsearch
    Args:
        cve_info_list (list): list of dict. e.g.
            [{'CVE': 'CVE-2020-25681',
              'CVSSScoreSets': {'ScoreSet': {'BaseScore': '8.1',
                                             'Vector': 'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'}},
              'Notes': {'Note': {'Ordinal': '1',
                                 'Title': 'Vulnerability Description',
                                 'Type': 'General',
                                 'text': 'A long description',
                                 '{http://www.w3.org/XML/1998/namespace}lang': 'en'}},
              'Ordinal': '1',
              'ProductStatuses': {'Status': {'ProductID': ['openEuler-20.03-LTS',
                                                           'openEuler-20.03-LTS-SP1'],
                                             'Type': 'Fixed'}},
              'ReleaseDate': '2021-01-21',
              'Remediations': {'Remediation': {'DATE': '2021-01-21',
                                               'Description': 'dnsmasq security update',
                                               'Type': 'Vendor Fix',
                                               'URL': 'security advisory url'}},
              'Threats': {'Threat': {'Description': 'High', 'Type': 'Impact'}}}]

        srcpackage_list(list): list of Source package name.

        package_info_list(list): Software package information, e.g.
            [{'FullProductName': [{'CPE': 'cpe:/a:openEuler:openEuler:20.03-LTS-SP3',
                                   'ProductID': 'vim-debugsource-8.2-12',
                                   'text': 'vim-debugsource-8.2-11.oe1.aarch64.rpm'},
                                  {'CPE': 'cpe:/a:openEuler:openEuler:20.03-LTS-SP3',
                                   'ProductID': 'vim-debuginfo-8.2-12',
                                   'text': 'vim-debuginfo-8.2-11.oe1.aarch64.rpm'}],
              'Name': 'openEuler',
              'Type': 'Product Name'}]


    Returns:
        list: list of dict for mysql Cve table. e.g.
            [{
                "cve_id": "cve-2021-1001",
                "publish_time": "2021-1-1",  // here is advisory's publish time actually
                "severity": "high",
                "cvss_score": "5.9",
                "reboot": False  // need reboot or not is default False for now
            }]
        list: list of dict for mysql CveAffectedPkgs table. e.g.
            [{
                "cve_id": "cve-2021-1001",
                "package": "redis",
                "package_version": "1.2",
                "os_version": "openEuler-20.03-LTS",
                "affected": True
            }]
        dict: cve id mapped with its description
    """
    cve_table_rows_dict = {}
    cve_pkg_rows = []
    cve_description = {}
    package_os_version = {}
    for package_info in package_info_list:
        # Branch Name is not "openEuler", don`t get the os version
        if package_info["Name"] != "openEuler":
            continue
        full_product_name = package_info.get("FullProductName")
        if not full_product_name:
            continue
        if isinstance(full_product_name, dict):
            full_product_name = [full_product_name]
        for srcpackage in srcpackage_list:
            for product in full_product_name:
                package_os_version[product["text"]] = srcpackage

    for cve_info in cve_info_list:
        cve_id = cve_info["CVE"]
        if cve_id in cve_table_rows_dict:
            raise ParseAdvisoryError("The advisory has multiple CVE info for the CVE '%s'." % cve_id)
        cve_table_rows_dict[cve_id] = {
            "cve_id": cve_id,
            "publish_time": cve_info["ReleaseDate"],
            "severity": cve_info["Threats"]["Threat"]["Description"],
            "cvss_score": cve_info["CVSSScoreSets"]["ScoreSet"]["BaseScore"],
            "reboot": False,
        }
        for os_version, srcpackage in package_os_version.items():
            cve_pkg_rows.append(
                {
                    "cve_id": cve_id,
                    "package": srcpackage,
                    "package_version": "",
                    "os_version": os_version,
                    "affected": True,
                }
            )

        # some cve may not have the 'text' key, which is description
        description = cve_info["Notes"]["Note"].get("text", "")
        cve_description[cve_id] = description

    return list(cve_table_rows_dict.values()), cve_pkg_rows, cve_description


def parse_arch_info(cve_description):
    """
    get es cve fixing documents for elasticsearch insertion
    Args:
        cve_description (dict): cve id mapped with its description
    Returns:
        list: e.g.
            [{
                'cve_id': 'CVE-2021-43809',
                'description': 'a long description',
            }]
    """
    doc_list = []
    for cve_id, description in cve_description.items():
        doc_dict = {"cve_id": cve_id, "description": description}
        doc_list.append(doc_dict)
    return doc_list
