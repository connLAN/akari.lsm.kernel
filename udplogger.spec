Summary: A utility for receiving netconsole messages.
Name: udplogger
Version: 1.0
Release: 1
License: GPLv2
Group: Applications/System
ExclusiveOS: Linux
Autoreqprov: no
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Conflicts: udplogger < 1.0-1

Source0: udplogger-1.0.tar.gz

%description
This package contains a utility for receiving netconsole messages.

%prep

%setup -q -n udplogger

%build

make CFLAGS="-Wall $RPM_OPT_FLAGS"

%install

rm -rf $RPM_BUILD_ROOT
make INSTALLDIR=$RPM_BUILD_ROOT install

%clean

rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/usr/bin/udplogger
%doc /usr/share/doc/udplogger/README
%doc /usr/share/doc/udplogger/COPYING

%changelog
* Mon Mar 10 2014 1.0-1
- Initial packaging.
