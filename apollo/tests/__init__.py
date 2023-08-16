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
import unittest
from unittest import TestCase

from vulcanus.conf import configuration
from vulcanus.manage import init_application
from apollo.conf import configuration as settings
from apollo.url import URLS


class BaseTestCase(TestCase):
    def setUp(self) -> None:
        for config in [config for config in dir(settings) if not config.startswith("_")]:
            setattr(configuration, config, getattr(settings, config))

    @staticmethod
    def create_app():
        app = init_application(name="apollo", settings=settings, register_urls=URLS)
        app.testing = True
        return app.test_client()


if __name__ == "__main__":
    unittest.main()
