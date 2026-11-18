Name:           presswork
Version:        0.1.0
Release:        1%{?dist}
Summary:        Memory-safe CUPS-compatible print spooler and IPP scheduler
License:        Apache-2.0 OR MIT
URL:            https://github.com/vindeckyy/presswork
Source0:        %{url}/archive/refs/tags/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  systemd-rpm-macros
Recommends:     cups-filters
Suggests:       cups-client
Provides:       cups
Provides:       cups-daemon
Conflicts:      cups

%description
presswork is a from-scratch reimplementation of the CUPS 2.x print
spooler and IPP scheduler in Rust — driverless IPP first, with a PPD /
legacy-driver layer for parity. It speaks the same IPP on the same
sockets, reads /etc/cups config in place, and keeps the same
filter/backend contracts, so existing clients, queues, and admin tools
work unmodified.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --workspace --release --frozen

%install
# Unprivileged staging: CHOWN=0 avoids chown during mock/rpmbuild and
# INSTALL_DOCS=0 prevents conflicts with RPM's %doc macro.
make install-files DESTDIR=%{buildroot} \
    PREFIX=%{_prefix} \
    UNITDIR=%{_unitdir} \
    TMPFILESDIR=%{_tmpfilesdir} \
    SYSUSERSDIR=%{_sysusersdir} \
    PAMDIR=%{_sysconfdir}/pam.d \
    LOGROTATEDIR=%{_sysconfdir}/logrotate.d \
    PROFILE=release \
    CHOWN=0 \
    INSTALL_DOCS=0
# /run/cups is managed by systemd-tmpfiles and declared %ghost below.
rm -rf %{buildroot}/run/cups

%pre
# Create lp user/group and lpadmin group. Do NOT add lp to lpadmin so
# unprivileged filters/backends cannot gain @SYSTEM admin rights.
getent group lp >/dev/null || groupadd -r lp
getent passwd lp >/dev/null || \
    useradd -r -g lp -d /var/spool/cups -s /sbin/nologin \
        -c "Printing system" lp
getent group lpadmin >/dev/null || groupadd -r lpadmin
exit 0

%post
%tmpfiles_create %{_tmpfilesdir}/presswork.conf
%systemd_post cups.service cups.socket cups.path
chgrp lp /etc/cups /etc/cups/cupsd.conf /etc/cups/cups-files.conf \
    /etc/cups/cupsd.conf.default /etc/cups/cups-files.conf.default 2>/dev/null || :
chown root:root /etc/cups/ssl 2>/dev/null || :
chmod 0700 /etc/cups/ssl 2>/dev/null || :
chown -R lp:lp /var/spool/cups /var/log/cups /var/cache/cups 2>/dev/null || :

%preun
%systemd_preun cups.service cups.socket cups.path cups-lpd.socket

%postun
%systemd_postun_with_restart cups.service

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md SECURITY.md CHANGELOG.md
%{_sbindir}/cupsd
%{_bindir}/cupsfilter
%{_prefix}/lib/cups/
%{_datadir}/cups/
%dir %attr(0755,root,lp) %{_sysconfdir}/cups
%dir %attr(0755,root,root) %{_sysconfdir}/cups/ppd
%dir %attr(0755,root,root) %{_sysconfdir}/cups/interfaces
%dir %attr(0700,root,root) %{_sysconfdir}/cups/ssl
%config(noreplace) %attr(0640,root,lp) %{_sysconfdir}/cups/cupsd.conf
%config(noreplace) %attr(0640,root,lp) %{_sysconfdir}/cups/cups-files.conf
%attr(0640,root,lp) %{_sysconfdir}/cups/cupsd.conf.default
%attr(0640,root,lp) %{_sysconfdir}/cups/cups-files.conf.default
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/pam.d/cups
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/logrotate.d/presswork
%dir %attr(0710,lp,lp) /var/spool/cups
%dir %attr(0710,lp,lp) /var/spool/cups/tmp
%dir %attr(0755,lp,lp) /var/log/cups
%dir %attr(0770,lp,lp) /var/cache/cups
%dir %attr(0770,lp,lp) /var/cache/cups/rss
%ghost %dir %attr(0755,lp,lp) /run/cups
%ghost %dir %attr(0755,lp,lp) /run/cups/certs
%{_unitdir}/cups.service
%{_unitdir}/cups.socket
%{_unitdir}/cups.path
%{_unitdir}/cups-lpd@.service
%{_unitdir}/cups-lpd.socket
%{_tmpfilesdir}/presswork.conf
%{_sysusersdir}/presswork.conf

%changelog
* Wed Nov 18 2026 vindeckyy <35399491+vindeckyy@users.noreply.github.com> - 0.1.0-1
- Initial package with hardened systemd units, tmpfiles.d, sysusers.d, and unprivileged build
