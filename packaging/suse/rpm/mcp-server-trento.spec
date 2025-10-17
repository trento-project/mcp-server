#
# spec file for package mcp-server-trento
#
# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: Apache-2.0
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.
#
# Please submit bugfixes or comments via https://bugs.opensuse.org/
#

Name:           mcp-server-trento
Version:        0
Release:        0
License:        Apache-2.0
Summary:        Model Context Protocol server wrapping Trento API
Group:          System/Monitoring
URL:            https://github.com/trento-project/mcp-server
Source:         %{name}-%{version}.tar.gz
Source1:        vendor.tar.gz
ExclusiveArch:  x86_64 ppc64le s390x
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildRequires:  golang(API) = 1.25
Provides:       %{name} = %{version}-%{release}

%description
Trento is an open cloud-native web application for SAP Applications administrators.

Trento Model Context Protocol (MCP) server is a wrapper around the Trento API to be consumed by LLMs and other AI tools.

%prep
%setup -q            # unpack project sources
%setup -q -T -D -a 1 # unpack go dependencies in vendor.tar.gz, which was prepared by the source services

%define binaryname mcp-server-trento

%build
# Use the Makefile to build the binary
VERSION=%{version} BUILD_OUTPUT="%{binaryname}" CGO_ENABLED=1 make build

%check
echo "No test suite defined."

%install

# Remove executable bit from files
find . -type f \( -name '*.adoc' -o -name '*.md' -o -name '*.yaml' -o -name 'LICENSE' -o -name 'Dockerfile' \) -exec chmod -x {} +

# Install the binary from the local build directory to the buildroot.
install -D -m 0755 %{binaryname} "%{buildroot}%{_bindir}/%{binaryname}"

# Install the systemd unit
install -D -m 0644 packaging/suse/rpm/systemd/mcp-server-trento.service %{buildroot}%{_unitdir}/mcp-server-trento.service

# Install example configuration file
install -D -m 0600 packaging/suse/rpm/systemd/mcp-server-trento.example %{buildroot}%{_distconfdir}/trento/mcp-server-trento.example

# Add rc symlink
mkdir -p %{buildroot}/usr/sbin
ln -sf /usr/sbin/service %{buildroot}/usr/sbin/rc%{binaryname}

%pre
%service_add_pre mcp-server-trento.service

%post
%service_add_post mcp-server-trento.service

%preun
%service_del_preun mcp-server-trento.service

%postun
%service_del_postun mcp-server-trento.service

%files
%defattr(-,root,root)

%{_bindir}/%{binaryname}
%{_unitdir}/%{binaryname}.service
%{_sbindir}/rc%{binaryname}
%dir %{_distconfdir}/trento
%config %{_distconfdir}/trento/mcp-server-trento.example

%license LICENSE

%doc README.adoc docs

%changelog
