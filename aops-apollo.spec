Name:		aops-apollo
Version:	v2.0.0
Release:	1
Summary:	Cve management service, monitor machine vulnerabilities and provide fix functions.
License:	MulanPSL2
URL:		https://gitee.com/openeuler/%{name}
Source0:	%{name}-%{version}.tar.gz

BuildRequires:  python3-setuptools
Requires:   aops-vulcanus >= v2.0.0
Requires:   python3-gevent python3-uWSGI python3-celery
Provides:   aops-apollo


%description
Cve management service, monitor machine vulnerabilities and provide fix functions.

%package -n aops-apollo-tool
Summary: Small tools for aops-apollo, e.g. updateinfo.xml generater
Requires: python3-rpm

%description -n aops-apollo-tool
smalltools for aops-apollo, e.g.updateinfo.xml generater

%prep
%autosetup -n %{name}-%{version}


# build for aops-apollo
%py3_build

# build for aops-apollo-tool
pushd aops-apollo-tool
%py3_build
popd

# install for aops-apollo
%py3_install
mkdir -p %{buildroot}/opt/aops/
cp -r database %{buildroot}/opt/aops/

# install for aops-apollo-tool
pushd aops-apollo-tool
%py3_install
popd


%files
%doc README.*
%attr(0644,root,root) %{_sysconfdir}/aops/conf.d/aops-apollo.yml
%attr(0755,root,root) %{_unitdir}/aops-apollo.service
%{python3_sitelib}/aops_apollo*.egg-info/*
%{python3_sitelib}/apollo/*
%attr(0755, root, root) /opt/aops/database/*

%files -n aops-apollo-tool
%attr(0644,root,root) %{_sysconfdir}/aops_apollo_tool/updateinfo_config.ini
%attr(0755,root,root) %{_bindir}/gen-updateinfo
%{python3_sitelib}/aops_apollo_tool*.egg-info/*
%{python3_sitelib}/aops_apollo_tool/*

%changelog
%changelog
* Thu Jul 16 2024 luxuexian<luxuexian@huawei.com> - v2.0.0-1
- Update to v2.0.0
- Add cluster management and user auth management

* Thu Oct 19 2023 gongzhengtang<gong_zhengtang@163.com> - v1.3.3-1
- Remove hotpatch

* Tue May 23 2023 zhu-yuncheng<zhuyuncheng@huawei.com> - v1.2.1-1
- Better dnf hotpatch plugin for more syscare command
- Add updateinfo.xml generation tool

* Thu May 11 2023 ptyang<1475324955@qq.com> - v1.2.0-4
- Add network request exception capture

* Tue May 9 2023 ptyang<1475324955@qq.com> - v1.2.0-3
- fix send two emails bug

* Thu Apr 27 2023 ptyang<1475324955@qq.com> - v1.2.0-2
- fix args not effective bug
- download SA using a collaborative process

* Mon Apr 17 2023 gongzhengtang<gong_zhengtang@163.com> - v1.2.0-1
- add updated security advisory at regular time
- add execute the CVE scan command at regular time
- add correct abnormal data at regular time
- add dnf hotpatch list plugin

* Tue Dec 27 2022 wenxin<shusheng.wen@outlook.com> - v1.1.2-3
- modify version for vulcanus

* Thu Dec 15 2022 ptyang<1475324955@qq.com> - v1.1.2-2
- fix "PARTIAL_SUCCEED" bug

* Wed Dec 07 2022 wenxin<shusheng.wen@outlook.com> - v1.1.2-1
- modify status code for upload security advisories;fix cve query error

* Mon Dec 05 2022 gongzhengtang<gong_zhengtang@163.com> - v1.1.1-3
- Avoid the occasional 500 or query error when the api
- service is started through uwsgi

* Fri Dec 02 2022 gongzhengtang<gong_zhengtang@163.com> - v1.1.1-2
- fix param length validate and other bugs

* Fri Dec 02 2022 wenxin<shusheng.wen@outlook.com> - v1.1.1-1
- fix some bugs

* Sat Nov 26 2022 gongzhengtang<gong_zhengtang@163.com> - v1.1.0-2
- Fix param limit of length

* Fri Nov 25 2022 wenxin<shusheng.wen@outlook.com> - v1.1.0-1
- version update

* Wed Oct 19 2022 zhuyuncheng<zhuyuncheng@huawei.com> - v1.0.0-1
- Package init
