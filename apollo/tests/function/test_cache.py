#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
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
Description:
"""
import unittest

from apollo.function.cache import LRUCache


class TestCache(unittest.TestCase):
    def setUp(self):
        self.cache = LRUCache(2)

    def test_common(self):
        self.cache.put("a", [1])
        self.cache.put("b", 2)
        self.cache.put("a", 3)

        self.assertEqual(len(self.cache.queue), 2)

        res = self.cache.get("a")
        self.assertEqual(res, 3)
