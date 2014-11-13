
Name: app-mail-filter
Epoch: 1
Version: 1.6.7
Release: 1%{dist}
Summary: Mail Filter Engine - Core
License: LGPLv3
Group: ClearOS/Libraries
Source: app-mail-filter-%{version}.tar.gz
Buildarch: noarch

%description
The Mail Filter Engine provides a core set of tools for filtering inbound and outbound mail messages.

%package core
Summary: Mail Filter Engine - Core
Requires: app-base-core
Requires: app-base-core >= 1:1.6.5
Requires: app-events-core
Requires: app-mail-routing-core
Requires: app-network-core
Requires: app-smtp-core >= 1:1.5.40
Requires: amavisd-new >= 2.6.5

%description core
The Mail Filter Engine provides a core set of tools for filtering inbound and outbound mail messages.

This package provides the core API and libraries.

%prep
%setup -q
%build

%install
mkdir -p -m 755 %{buildroot}/usr/clearos/apps/mail_filter
cp -r * %{buildroot}/usr/clearos/apps/mail_filter/

install -d -m 0755 %{buildroot}/var/clearos/mail_filter
install -d -m 0755 %{buildroot}/var/clearos/mail_filter/backup
install -D -m 0644 packaging/amavisd.php %{buildroot}/var/clearos/base/daemon/amavisd.php
install -D -m 0644 packaging/api.conf %{buildroot}/etc/amavisd/api.conf
install -D -m 0755 packaging/smtp-event %{buildroot}/var/clearos/events/smtp/mail_filter

%post core
logger -p local6.notice -t installer 'app-mail-filter-core - installing'

if [ $1 -eq 1 ]; then
    [ -x /usr/clearos/apps/mail_filter/deploy/install ] && /usr/clearos/apps/mail_filter/deploy/install
fi

[ -x /usr/clearos/apps/mail_filter/deploy/upgrade ] && /usr/clearos/apps/mail_filter/deploy/upgrade

exit 0

%preun core
if [ $1 -eq 0 ]; then
    logger -p local6.notice -t installer 'app-mail-filter-core - uninstalling'
    [ -x /usr/clearos/apps/mail_filter/deploy/uninstall ] && /usr/clearos/apps/mail_filter/deploy/uninstall
fi

exit 0

%files core
%defattr(-,root,root)
%exclude /usr/clearos/apps/mail_filter/packaging
%dir /usr/clearos/apps/mail_filter
%dir /var/clearos/mail_filter
%dir /var/clearos/mail_filter/backup
/usr/clearos/apps/mail_filter/deploy
/usr/clearos/apps/mail_filter/language
/usr/clearos/apps/mail_filter/libraries
/var/clearos/base/daemon/amavisd.php
%config(noreplace) /etc/amavisd/api.conf
/var/clearos/events/smtp/mail_filter
