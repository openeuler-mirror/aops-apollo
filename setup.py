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
    'elasticsearch',
    'marshmallow>=3.13.0',
    'Flask',
    'Flask-RESTful',
    'Flask-APScheduler',
    'setuptools',
    'SQLAlchemy',
    'PyYAML'
]

setup(
    name=NAME,
    version=VERSION,
    description="aops-apollo",
    install_requires=REQUIRES,
    packages=find_packages(),
    data_files=[
        ('/etc/aops', ['conf/apollo.ini']),
        ('/etc/aops', ['conf/crontab.ini']),
        ('/usr/lib/systemd/system', ['aops-apollo.service'])
    ],
    # scripts=['aops-apollo'],
    entry_points={
        "console_scripts": ['aops-apollo=apollo.manage:main']
    },
    zip_safe=False
)
