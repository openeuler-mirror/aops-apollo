class Hotpatch(object):
    __slots__ = ['_name', '_version', '_cves',
                 '_advisory', '_arch', '_filename', '_state']

    def __init__(self,
                 name,
                 version,
                 arch,
                 filename,
                 release=''):
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

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        self._state = value

    @property
    def name(self):
        """
        name: patch-src_pkg-HPxxx
        """
        return self._name

    @property
    def version(self):
        return self._version

    @property
    def src_pkg(self):
        """
        If the hotpatch need to be installed, the source package must be installed
        
        src_pkg: name-version-release
        """
        src_pkg = self.name[self.name.index('-')+1:self.name.rindex('-')]
        return src_pkg

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
        src_pkg_name, src_pkg_version, src_pkg_release = src_pkg[
            0:version_pos], src_pkg[version_pos+1:release_pos], src_pkg[release_pos+1:]
        return src_pkg_name, src_pkg_version, src_pkg_release

    @property
    def nevra(self):
        """
        Format the filename as 'name-versioin-release.arch' for display, which is defined as nevra

        nevra: name-version-release.arch
        """
        return self.filename[0:self.filename.rindex('.')]

    @property
    def hotpatch_name(self):
        """
        The 'hotpatch_name' is defined as HPxxx, which is used for hotpatch status querying in syscare
        """
        hotpatch_name = self.name[self.name.rindex('-')+1:]
        return hotpatch_name

    @property
    def syscare_name(self):
        src_pkg = '%s-%s-%s' % (self.src_pkg_nevre)
        return '%s/%s' % (src_pkg, self.hotpatch_name)

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

    def __init__(self,
                 id,
                 **kwargs):
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
    __slots__ = ['_id', '_adv_type', '_title', '_severity',
                 '_description', '_updated', '_hotpatches', '_cves']

    def __init__(self,
                 id,
                 adv_type,
                 title,
                 severity,
                 description,
                 updated="1970-01-01 08:00:00",
                 **kwargs):
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

