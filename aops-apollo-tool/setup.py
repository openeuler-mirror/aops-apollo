# coding: utf-8

from setuptools import setup, find_packages

NAME = "aops_apollo_tool"
VERSION = "1.2.1"

# To install the library, run the following
#
# python setup.py install
#
# prerequisite: setuptools
# http://pypi.python.org/pypi/setuptools

REQUIRES = [
]

setup(
    name=NAME,
    version=VERSION,
    description="aops_apollo_tool",
    install_requires=REQUIRES,
    packages=find_packages(),
    data_files=[
        ('/etc/aops_apollo_tool', ['updateinfo_config.ini']),
    ],
    entry_points={
        "console_scripts": ['gen-updateinfo=aops_apollo_tool.gen_updateinfo:main']
            },
    zip_safe=False
)
