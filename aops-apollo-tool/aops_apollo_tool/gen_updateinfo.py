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
Time: 2023/05/16
Author: wang guangge
Description: generate updateinfo.xml
"""
import argparse
import configparser
import os
import re
import sys
import xml.etree.ElementTree as ET
from xml.dom import minidom
from xml.etree.ElementTree import Element

import rpm

# get updateinfo global config
UPDATEINFO_FILE = "/etc/aops_apollo_tool/updateinfo_config.ini"
CONF = configparser.ConfigParser()
CONF.read(filenames=UPDATEINFO_FILE)


def parse_updateinfo_xml_file_to_ET(input_updateinfo_xml_path: str) -> ET:
    """
    Parse the updateinfo.xml as ElementTree.

    Returns:
        ElementTree
    """
    if not os.path.exists(input_updateinfo_xml_path):
        print('error: %s does not exist. Please check the path.' % input_updateinfo_xml_path)
        sys.exit(1)

    try:
        tree = ET.parse(input_updateinfo_xml_path)
    except ET.ParseError as e:
        print("error: %s cannot be successfully parsed : %s." % (input_updateinfo_xml_path, e))
        sys.exit(1)

    return tree


def check_uniqueness_of_advisory_id(root: ET, advisory_id: str) -> int:
    """
    By default, the advisory id in each advisory of the updateinfo.xml is unique. Exit if the
    advisory id is duplicated.
    """
    existed_adv_id = {advisory_id}
    for update in root.iter('update'):

        adv_id = update.find('id')
        if adv_id is not None:
            update_adv_id = adv_id.text
        else:
            print("error: the required paramter of advisory id is missing in the input file.")
            sys.exit(1)

        if update_adv_id in existed_adv_id:
            print("error: the advisory id \'%s\' is duplicated in the input file." % update_adv_id)
            sys.exit(1)
        existed_adv_id.add(update_adv_id)


def parse_src_rpm_info_by_filename(filename: str) -> tuple:
    """
    Parse source rpm package information by filename, the filename should be 'name-version-release.src.rpm'.

    Returns:
        name, version, release
    """
    nevra_pos = filename.rindex('.src.rpm')
    nevra = filename[:nevra_pos]
    release_pos = nevra.rindex('-')
    version_pos = nevra.rindex('-', 0, release_pos)
    name, version, release = nevra[0:version_pos], nevra[version_pos + 1 : release_pos], nevra[release_pos + 1 :]

    return name, version, release


def generate_package_list(package_dir: str) -> Element:
    """
    Traverse the rpm packages in the package directory. Generate Element 'package' for each successfully
    parsed rpm package. Element 'collection" is composed of Element 'package'. Element 'pkglist' is
    composed of Element 'collection'.

    e.g.
    <pkglist>
        <collection>
            <package arch="x86_64" name="patch-redis-6.2.5-1-HP001" release="1" version="1">
                <filename>patch-redis-6.2.5-1-HP001-1-1.x86_64.rpm</filename>
            </package>
            <package arch="aarch64" name="patch-redis-6.2.5-1-HP001" release="1" version="1">
                <filename>patch-redis-6.2.5-1-HP001-1-1.aarch64.rpm</filename>
            </package>
        </collection>
    </pkglist>

    Returns:
        Element 'pkglist'
    """
    ts = rpm.ts()
    pkg_list = Element('pkglist')
    collection = Element('collection')
    for pkg in os.listdir(package_dir):
        if os.path.splitext(pkg)[1] != '.rpm':
            continue

        package = Element('package')
        package_path = os.path.join(package_dir, pkg)

        try:
            with open(package_path, 'r') as f:
                pkg_info = ts.hdrFromFdno(f)
        except rpm.error:
            print("error: %s cannot be successfully parsed" % package_path)
            sys.exit(1)

        filename = Element('filename')
        if pkg.endswith('.src.rpm'):
            # parse source rpm information by filename, and the arch information is not marked
            name, version, release = parse_src_rpm_info_by_filename(pkg)
            package.attrib['name'] = name
            package.attrib['version'] = version
            package.attrib['release'] = release
            filename.text = pkg

        else:
            package.attrib['arch'] = pkg_info[rpm.RPMTAG_ARCH]
            package.attrib['name'] = pkg_info[rpm.RPMTAG_NAME]
            package.attrib['version'] = pkg_info[rpm.RPMTAG_VERSION]
            package.attrib['release'] = pkg_info[rpm.RPMTAG_R]

            filename.text = "%s-%s-%s.%s.rpm" % (
                package.attrib['name'],
                package.attrib['release'],
                package.attrib['version'],
                package.attrib['arch'],
            )

        package.append(filename)
        collection.append(package)

    pkg_list.append(collection)
    return pkg_list


def generate_references(reference_type: str, reference_id: list, reference_href: list) -> Element:
    """
    Generate references according to the args.
    e.g.
    <references>
        <reference href="https://gitee.com/src-openeuler/redis/issues/I6IRPL?from=project-issue" id="CVE-2023-25155" title="CVE-2023-25155" type="cve"/>
        <reference href="https://gitee.com/src-openeuler/redis/issues/I5YBKE?from=project-issue" id="CVE-2022-3734" title="CVE-2022-3734" type="cve"/>
        </references>

    e.g.
    <references>
        <reference href="https://gitee.com/wang-guangge/redis/issues/I6X4XN" id="I6X4XN" title="I6X4XN" type="bugfix"/>
        </references>

    Returns:
        Element 'references'
    """

    references = Element('references')
    reference_info = {id: dict() for id in reference_id}
    if reference_href:
        for id, href in zip(reference_id, reference_href):
            reference_info[id]['href'] = href

    for id in reference_id:
        reference = Element('reference')
        if 'href' in reference_info[id].keys():
            reference.attrib['href'] = reference_info[id]['href']
        reference.attrib['id'] = id
        reference.attrib['title'] = id
        reference.attrib['type'] = reference_type
        references.append(reference)

    return references


def generate_advisory(args) -> Element:
    """
    Generate the advisory according to the args.

    e.g.
        <update from="openeuler.org" type="security" status="stable">
                <id>CVE-2021-32675</id>
                <title>Fix prevent unauthenticated client from easily consuming lots of memory</title>
                <severity>Critical</severity>
                <release>openEuler</release>
        <issued date="2023-01-01"></issued>
                <references>
                        <reference href="https://gitee.com/wang-guangge/redis/issues/I6X4XN" id="CVE-2021-32675" title="CVE-2021-32675" type="cve"/>
                </references>
                <description>description.</description>
                <pkglist>
                        <collection>
                                <package arch="x86_64" name="patch-redis-6.2.5-1-HP001" release="1" version="1">
                                        <filename>patch-redis-6.2.5-1-HP001-1-1.x86_64.rpm</filename>
                                </package>
                                <package arch="aarch64" name="patch-redis-6.2.5-1-HP001" release="1" version="1">
                                        <filename>patch-redis-6.2.5-1-HP001-1-1.aarch64.rpm</filename>
                                </package>
                        </collection>
                </pkglist>
        </update>

    Returns:
        Element 'update'
    """
    # get global config parameters
    update_from = CONF.get(section='global_config', option='update_from')
    update_release = CONF.get(section='global_config', option='update_release')

    update = Element('update')
    update.attrib['from'] = update_from
    update.attrib['type'] = args.update_type
    update.attrib['status'] = args.update_status
    adv_id = Element('id')
    adv_id.text = args.id
    update.append(adv_id)
    title = Element('title')
    title.text = args.title
    update.append(title)
    if args.severity:
        severity = Element('severity')
        severity.text = args.severity
        update.append(severity)
    release = Element('release')
    release.text = update_release
    update.append(release)
    if args.issued_date:
        issued = Element('issued')
        issued.attrib['date'] = args.issued_date
        update.append(issued)

    references = generate_references(args.reference_type, args.reference_id, args.reference_href)
    update.append(references)

    if args.description:
        description = Element('description')
        description.text = args.description
        update.append(description)

    pkg_list = generate_package_list(args.package_dir)
    update.append(pkg_list)

    return update


def gene_advisory_and_add_in_updateinfo_xml(args) -> None:
    """
    Generate an advisory according to the args and add the advisory in the updateinfo.xml.
    """
    output_updateinfo_xml_path = args.output_path
    input_updateinfo_xml_path = args.input_path
    update = generate_advisory(args)

    if args.input_path:
        tree = parse_updateinfo_xml_file_to_ET(input_updateinfo_xml_path)
        root = tree.getroot()
        check_uniqueness_of_advisory_id(root, args.id)
    else:
        updates = ET.Element("updates")
        tree = ET.ElementTree(updates)
        root = tree.getroot()

    root.append(update)

    write_to_updateinfo_xml(root, output_updateinfo_xml_path)


def write_to_updateinfo_xml(root: ET, output_updateinfo_xml_path: str) -> None:
    """
    Convert the ElementTree into a formated string, and write it to the output path.
    """
    raw_text = ET.tostring(root)
    dom = minidom.parseString(raw_text)
    pretty_text = dom.toprettyxml(indent='\t')
    new_pretty_text = re.sub('\n[\s|]*\n', '\n', pretty_text)
    with open(output_updateinfo_xml_path, 'w') as f:
        f.write(new_pretty_text)


def main():
    parser = argparse.ArgumentParser(description='generate updateinfo.xml')
    # required parameters
    parser.add_argument(
        'update_type', type=str, choices=['security', 'bugfix', 'enhancement'], help='(security/bugfix/enhancement)'
    )
    parser.add_argument('title', type=str)
    parser.add_argument('id', type=str)
    parser.add_argument(
        '--reference-type', type=str, required=True, choices=['cve', 'bugfix', 'feature'], help='(cve/bugfix/feature)'
    )
    parser.add_argument('--reference-id', type=str, nargs='+', required=True)
    # optional paramters
    parser.add_argument('--description', type=str, required=False)
    parser.add_argument(
        '--severity',
        type=str,
        choices=['Critical', 'Important', 'Moderate', 'Low'],
        help='(Critical/Important/Moderate/Low)',
        required=False,
    )
    parser.add_argument(
        '--reference-href',
        type=str,
        nargs='+',
        required=False,
        help='(Corresponding to the reference-id)',
    )
    parser.add_argument('--update-status', type=str, default='stable', required=False, help='(Default: stable)')
    parser.add_argument('--issued-date', type=str, required=False)
    # package directory
    parser.add_argument(
        '--package-dir',
        type=str,
        required=True,
        help='(Collect rpm package information from the package directory.)',
    )
    # input path
    parser.add_argument(
        '-i',
        '--input-path',
        type=str,
        required=False,
        help='(If input path is not none, the new advisory will be appended and written to the output path.)',
    )
    # output path
    parser.add_argument(
        '-o',
        '--output-path',
        type=str,
        default='./updateinfo.xml',
        required=False,
        help='(Default: ./updateinfo.xml)',
    )
    args = parser.parse_args()

    if args.reference_href and len(args.reference_href) != len(args.reference_id):
        print("error: reference-href and reference-id must have the same number of parameters.")
        sys.exit(1)

    gene_advisory_and_add_in_updateinfo_xml(args)
    print("success: %s has been generated." % args.output_path)
    sys.exit(0)


main()
