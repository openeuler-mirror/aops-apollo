#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
# licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/
class Versions:
    """
    Version number processing
    """

    separator = (".", "-")
    _connector = "&"

    def _order(self, version, separator=None):
        """
        Version of the cutting
        Args:
            version: version
            separator: separator

        Returns:

        """
        if not separator:
            separator = self._connector
        return tuple([int(v) for v in version.split(separator) if v.isdigit()])

    def larger_than(self, version, compare_version):
        """
        Returns true if the size of the compared version is greater
        than that of the compared version, or false otherwise

        """
        for separator in self.separator:
            version = self._connector.join([v for v in version.split(separator)])
            compare_version = self._connector.join([v for v in compare_version.split(separator)])
        version = self._order(version)
        compare_version = self._order(compare_version)
        return version >= compare_version
