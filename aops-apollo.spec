Name:		aops-apollo
Version:	v2.0.0
Release:	1
Summary:	Cve management service, monitor machine vulnerabilities and provide fix functions.
License:	MulanPSL2
URL:		https://gitee.com/openeuler/%{name}
Source0:	%{name}-%{version}.tar.gz

BuildRequires:  python3-setuptools
Requires:   aops-vulcanus = %{version}-%{release}
Requires:   python3-elasticsearch python3-flask-restful python3-marshmallow >= 3.13.0
Requires:   python3-sqlalchemy python3-PyMySQL python3-Flask-APScheduler >= 1.11.0
Requires:   python3-PyYAML python3-flask
Provides:   aops-apollo


%description
Cve management service, monitor machine vulnerabilities and provide fix functions.


%prep
%autosetup -n %{name}-%{version}


# build for aops-apollo
%py3_build


# install for aops-apollo
%py3_install


%files
%doc README.*
%attr(0644,root,root) %{_sysconfdir}/aops/apollo.ini
%attr(0644,root,root) %{_sysconfdir}/aops/apollo_crontab.ini
%attr(0755,root,root) %{_bindir}/aops-apollo
%attr(0755,root,root) %{_unitdir}/aops-apollo.service
%{python3_sitelib}/aops_apollo*.egg-info
%{python3_sitelib}/apollo/*


%changelog
* Wed Oct 19 2022 zhuyuncheng<zhuyuncheng@huawei.com> - v2.0.0-1
- Package init
