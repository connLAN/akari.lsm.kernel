Summary: AKARI tools

Name: akari-tools
Version: 1.0
Release: 1
License: GPL
Group: System Environment/Kernel
ExclusiveOS: Linux
Autoreqprov: no
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Conflicts: akari-tools < 1.0-1

Source0: http://osdn.dl.sourceforge.jp/akari/?????/akari-tools-1.0-2010????.tar.gz

%description
This is AKARI tools.

%prep

%setup -q -n tools

%build

make -s all

%install

make -s install INSTALLDIR=%{buildroot}

%clean

rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/sbin/akari-init
/usr/lib/
/usr/sbin/
/usr/share/man/
%config(noreplace) /usr/lib/akari/akaritools.conf

%changelog
* ??? ??? ?? 2010 1.0-1
- First-release.
