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
class Hotpatch(object):
    __slots__ = [
        '_name',
        '_version',
        '_release',
        '_cves',
        '_advisory',
        '_arch',
        '_filename',
        '_state',
        '_required_pkgs_info',
        '_required_pkgs_str',
        '_required_pkgs_name_str',
    ]

    def __init__(self, name, version, arch, filename, release):
        """
        name: str
        version: str
        arch: str
        filename: str
        release: str
        """
        self._name = name
        self._version = version
        self._arch = arch
        self._filename = filename
        self._cves = []
        self._advisory = None
        self._state = ''
        self._release = release
        self._required_pkgs_info = dict()
        self._required_pkgs_str = ''
        self._required_pkgs_name_str = ''

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        self._state = value

    @property
    def name(self):
        """
        name: patch-src_pkg-ACC or patch-src_pkg-SGL_xxx
        """
        return self._name

    @property
    def version(self):
        return self._version

    @property
    def release(self):
        return self._release

    @property
    def src_pkg(self):
        """
        The compiled source package for hotpatch.

        src_pkg: name-version-release
        """
        src_pkg = self.name[self.name.index('-') + 1 : self.name.rindex('-')]
        return src_pkg

    @property
    def required_pkgs_info(self):
        """
        The target fixed rpm package of the hotpatch.
        """
        return self._required_pkgs_info

    @required_pkgs_info.setter
    def required_pkgs_info(self, required_pkgs_info):
        """
        The required pkgs info are from the 'dnf repoquery --requires name-version-release.arch'. The
        required pkgs info are considered to be truely fixed rpm package.

        e.g.
            {
                'redis': '6.2.5-1',
                'redis-cli': '6.2.5-1'
            }
        """

        self._required_pkgs_info = required_pkgs_info
        required_pkgs_str_list = []
        required_pkgs_name_str_list = []
        # sort the _required_pkgs_info and concatenate the str to get _required_pkgs_str
        for required_pkgs_name, required_pkgs_vere in self._required_pkgs_info.items():
            required_pkgs_str_list.append("%s-%s" % (required_pkgs_name, required_pkgs_vere))
            required_pkgs_name_str_list.append(required_pkgs_name)
        sorted(required_pkgs_str_list)
        sorted(required_pkgs_name_str_list)
        self._required_pkgs_str = ",".join(required_pkgs_str_list)
        self._required_pkgs_name_str = ",".join(required_pkgs_name_str_list)

    @property
    def required_pkgs_str(self):
        """
        The truly fixed rpm package mark, which is composed of required_pkgs_info.

        e.g.
            'redis-6.2.5-1,redis-cli-6.2.5-1'
        """
        return self._required_pkgs_str

    @property
    def required_pkgs_name_str(self):
        """
        The truly fixed rpm package name mark, which is composed of keys of required_pkgs_info.

        e.g.
            'redis,redis-cli'
        """
        return self._required_pkgs_name_str

    @property
    def src_pkg_nevre(self):
        """
        Parse the source package to get the source package name, the source package version and the source package release

        Returns:
            src_pkg_name, src_pkg_version, src_pkg_release
        """
        src_pkg = self.src_pkg
        release_pos = src_pkg.rindex('-')
        version_pos = src_pkg.rindex('-', 0, release_pos)
        src_pkg_name, src_pkg_version, src_pkg_release = (
            src_pkg[0:version_pos],
            src_pkg[version_pos + 1 : release_pos],
            src_pkg[release_pos + 1 :],
        )
        return src_pkg_name, src_pkg_version, src_pkg_release

    @property
    def nevra(self):
        """
        Format the filename as 'name-versioin-release.arch' for display, which is defined as nevra

        nevra: name-version-release.arch
        """
        return self.filename[0 : self.filename.rindex('.')]

    @property
    def hotpatch_name(self):
        """
        There are two types of hotpatch, ACC hotpatch and SGL hotpatch. The ACC hotpatch can be made
        iteratively, and its 'hotpatch_name' is defined as ACC. The SGL hotpatch cannot be made iteratively,
        and its 'hotpatch_name' is defined as SGL_xxx. The 'xxx' in the SGL_xxx means the issue it solves.
        """
        hotpatch_name = self.name[self.name.rindex('-') + 1 :]
        return hotpatch_name

    @property
    def syscare_subname(self):
        """
        The 'syscare_subname' is used for hotpatch status querying in syscare list, which is composed of
        'src_pkg/hotpatch_name-version-release'.
        """
        src_pkg = '%s-%s-%s' % (self.src_pkg_nevre)

        return '%s/%s-%s-%s' % (src_pkg, self.hotpatch_name, self.version, self.release)

    @property
    def cves(self):
        return self._cves

    @cves.setter
    def cves(self, cves):
        self._cves = cves

    @property
    def advisory(self):
        return self._advisory

    @advisory.setter
    def advisory(self, advisory):
        self._advisory = advisory

    @property
    def arch(self):
        return self._arch

    @property
    def filename(self):
        return self._filename


class Cve(object):
    __slots__ = ['_cve_id', '_hotpatches']

    def __init__(self, id, **kwargs):
        """
        id: str
        """
        self._cve_id = id
        self._hotpatches = []

    @property
    def hotpatches(self):
        return self._hotpatches

    def add_hotpatch(self, hotpatch: Hotpatch):
        self._hotpatches.append(hotpatch)

    @property
    def cve_id(self):
        return self._cve_id


class Advisory(object):
    __slots__ = ['_id', '_adv_type', '_title', '_severity', '_description', '_updated', '_hotpatches', '_cves']

    def __init__(self, id, adv_type, title, severity, description, updated="1970-01-01 08:00:00", **kwargs):
        """
        id: str
        adv_type: str
        title: str
        severity: str
        description: str
        updated: str
        """
        self._id = id
        self._adv_type = adv_type
        self._title = title
        self._severity = severity
        self._description = description
        self._updated = updated
        self._cves = {}
        self._hotpatches = []

    @property
    def id(self):
        return self._id

    @property
    def adv_type(self):
        return self._adv_type

    @property
    def title(self):
        return self._title

    @property
    def severity(self):
        return self._severity

    @property
    def description(self):
        return self._description

    @property
    def updated(self):
        return self._updated

    @property
    def cves(self):
        return self._cves

    @cves.setter
    def cves(self, advisory_cves):
        self._cves = advisory_cves

    @property
    def hotpatches(self):
        return self._hotpatches

    def add_hotpatch(self, hotpatch: Hotpatch):
        self._hotpatches.append(hotpatch)
