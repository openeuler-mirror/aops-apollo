# coding: utf-8

from setuptools import setup, find_packages

NAME = "aops-apollo"
VERSION = "2.0.0"

# To install the library, run the following
#
# python setup.py install
#
# prerequisite: setuptools
# http://pypi.python.org/pypi/setuptools

REQUIRES = [
    'celery',
    'elasticsearch',
    'marshmallow>=3.13.0',
    'Flask',
    'Flask-RESTful',
    'setuptools',
    'SQLAlchemy',
    'PyMySQL',
    'PyYAML',
    'redis',
    'retrying',
    'gevent',
]

setup(
    name=NAME,
    version=VERSION,
    description="aops-apollo",
    install_requires=REQUIRES,
    packages=find_packages(),
    data_files=[
        ('/etc/aops/conf.d', ['conf/aops-apollo.yml']),
        ('/usr/lib/systemd/system', ['aops-apollo.service']),
        ("/opt/aops/database", ["database/aops-apollo.sql"]),
    ],
    zip_safe=False,
)
