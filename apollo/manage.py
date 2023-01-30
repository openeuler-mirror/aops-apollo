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
Description: Manager that start aops-manager
"""
from flask import Flask
# from flask_apscheduler import APScheduler
import sqlalchemy
from apollo import BLUE_POINT
from apollo.conf import configuration
from apollo.cron.manager import TimedTaskManager
from apollo.database import ENGINE
from apollo.database.table import create_vul_tables
from apollo.database.mapping import MAPPINGS
from vulcanus.database.proxy import ElasticsearchProxy
from vulcanus.log.log import LOGGER


def init_mysql():
    """
    Initialize user, add a default user: admin
    """
    try:
        create_vul_tables(ENGINE)
        LOGGER.info("initialize mysql tables for aops-apollo succeed.")
    except sqlalchemy.exc.SQLAlchemyError as err:
        LOGGER.error(err)
        LOGGER.error("initialize mysql tables for aops-apollo failed.")
        raise sqlalchemy.exc.SQLAlchemyError("create tables fail")


def init_es():
    """
    Initialize elasticsearch index and add default task
    """
    proxy = ElasticsearchProxy(configuration)
    if not proxy.connect():
        raise ValueError("connect to elasticsearch fail")

    for index_name, body in MAPPINGS.items():
        res = proxy.create_index(index_name, body)
        if not res:
            raise ValueError("create elasticsearch index %s fail", index_name)

    LOGGER.info("create elasticsearch index succeed")
    # update es settings
    config = {
        "max_result_window": configuration.elasticsearch.get('MAX_ES_QUERY_NUM')
    }
    proxy.update_settings(**config)


def init_database():
    """
    Initialize database
    """
    init_mysql()
    init_es()


def init_app():
    app = Flask('apollo')
    # limit max upload document size
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
    TimedTaskManager().init_app(app)

    TimedTaskManager().start_task()
    for blue, api in BLUE_POINT:
        api.init_app(app)
        app.register_blueprint(blue)

    return app


def main():
    init_database()
    app = init_app()
    ip = configuration.apollo.get('IP')
    port = configuration.apollo.get('PORT')
    app.run(host=ip, port=port, use_reloader=False)


if __name__ == "__main__":
    main()
