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
from gevent import monkey

monkey.patch_all(thread=False)
import redis
import sqlalchemy
from flask import Flask
from redis import RedisError

from vulcanus.timed import TimedTaskManager
from vulcanus.database.proxy import ElasticsearchProxy, RedisProxy
from vulcanus.log.log import LOGGER
from apollo import BLUE_POINT
from apollo.conf import configuration
from apollo.conf.constant import TIMED_TASK_CONFIG_PATH
from apollo.cron import task_meta
from apollo.database import ENGINE
from apollo.database.mapping import MAPPINGS
from apollo.database.table import create_vul_tables


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
    config = {"max_result_window": configuration.elasticsearch.get('MAX_ES_QUERY_NUM')}
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

    for blue, api in BLUE_POINT:
        api.init_app(app)
        app.register_blueprint(blue)

    return app


def init_timed_task(app):
    """
    Initialize and create a scheduled task

    Args:
        app:flask.Application
    """
    timed_task = TimedTaskManager(app=app, config_path=TIMED_TASK_CONFIG_PATH)
    if not timed_task.timed_config:
        LOGGER.warning("If you want to start a scheduled task, please add a timed config.")
        return

    for task_info in timed_task.timed_config.values():
        task_type = task_info.get('type')
        if task_type not in task_meta:
            continue
        meta_class = task_meta[task_type]
        timed_task.add_job(meta_class(timed_config=task_info))

    timed_task.start()


def init_redis_connect():
    """
    Init redis connect
    """
    try:
        redis_connect = RedisProxy(configuration)
        redis_connect.connect()
    except (RedisError, redis.ConnectionError):
        raise RedisError("redis connect error.")


def main():
    init_redis_connect()
    init_database()
    app = init_app()
    init_timed_task(app)
    return app


app = main()
