#!/usr/bin/python
#
# Copyright 2016 Canonical Ltd.
#
# Authors:
#  James Page <james.page@ubuntu.com>
#  Edward Hope-Morley <edward.hope-morley@canonical.com>
#

import os
import subprocess
import sys

import ceph

from charmhelpers.core.hookenv import (
    relation_get,
    relation_ids,
    related_units,
    config,
    unit_get,
    open_port,
    relation_set,
    log,
    DEBUG,
    WARNING,
    ERROR,
    Hooks, UnregisteredHookError,
    status_set,
)
from charmhelpers.fetch import (
    apt_update,
    apt_install,
    apt_purge,
    add_source,
)
from charmhelpers.core.host import (
    lsb_release,
    restart_on_change,
)
from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.core.host import (
    cmp_pkgrevno,
    mkdir,
)
from charmhelpers.contrib.network.ip import (
    format_ipv6_addr,
    get_ipv6_addr,
    get_iface_for_address,
    get_netmask_for_address,
    is_ipv6,
)
from charmhelpers.contrib.openstack.ip import (
    canonical_url,
    PUBLIC, INTERNAL, ADMIN,
)
from charmhelpers.contrib.openstack.utils import (
    set_os_workload_status,
)
from charmhelpers.contrib.storage.linux.ceph import (
    send_request_if_needed,
    is_request_complete,
)
from utils import (
    enable_pocket,
    CEPHRG_HA_RES,
    register_configs,
    REQUIRED_INTERFACES,
    check_optional_relations,
    setup_ipv6,
    services,
)
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.contrib.hardening.harden import harden

hooks = Hooks()
CONFIGS = register_configs()
NSS_DIR = '/var/lib/ceph/nss'


def install_ceph_optimised_packages():
    """Inktank provides patched/optimised packages for HTTP 100-continue
    support that does has not yet been ported to upstream. These can
    optionally be installed from ceph.com archives.
    """
    prolog = "http://gitbuilder.ceph.com/"
    epilog = "-x86_64-basic/ref/master"
    rel = lsb_release()['DISTRIB_CODENAME']
    fastcgi_source = "%slibapache-mod-fastcgi-deb-%s%s" % (prolog, rel, epilog)
    apache_source = "%sapache2-deb-%s%s" % (prolog, rel, epilog)

    for source in [fastcgi_source, apache_source]:
        add_source(source, key='6EAEAE2203C3951A')


PACKAGES = [
    'radosgw',
    'ntp',
    'haproxy',
    'libnss3-tools',
    'python-keystoneclient',
    'python-six',  # Ensures correct version is installed for precise
                   # since python-keystoneclient does not pull in icehouse
                   # version
]

APACHE_PACKAGES = [
    'libapache2-mod-fastcgi',
    'apache2',
]


def install_packages():
    status_set('maintenance', 'Installing apt packages')
    add_source(config('source'), config('key'))
    if (config('use-ceph-optimised-packages') and
            not config('use-embedded-webserver')):
        install_ceph_optimised_packages()

    apt_update(fatal=True)
    apt_install(PACKAGES, fatal=True)
    if config('use-embedded-webserver'):
        apt_purge(APACHE_PACKAGES)
    else:
        apt_install(APACHE_PACKAGES, fatal=True)


@hooks.hook('install.real')
@harden()
def install():
    status_set('maintenance', 'Executing pre-install')
    execd_preinstall()
    enable_pocket('multiverse')
    install_packages()
    os.makedirs(NSS_DIR)
    if not os.path.exists('/etc/ceph'):
        os.makedirs('/etc/ceph')


def setup_keystone_certs(unit=None, rid=None):
    """
    Get CA and signing certs from Keystone used to decrypt revoked token list.
    """
    import requests

    try:
        # Kilo and newer
        from keystoneclient.exceptions import (
            ConnectionRefused,
            Forbidden
        )
    except ImportError:
        # Juno and older
        from keystoneclient.exceptions import (
            ConnectionError as ConnectionRefused,
            Forbidden
        )

    from keystoneclient.v2_0 import client

    certs_path = '/var/lib/ceph/nss'
    mkdir(certs_path)

    rdata = relation_get(unit=unit, rid=rid)
    auth_protocol = rdata.get('auth_protocol', 'http')

    required_keys = ['admin_token', 'auth_host', 'auth_port']
    settings = {}
    for key in required_keys:
        settings[key] = rdata.get(key)

    if is_ipv6(settings.get('auth_host')):
        settings['auth_host'] = format_ipv6_addr(settings.get('auth_host'))

    if not all(settings.values()):
        log("Missing relation settings (%s) - skipping cert setup" %
            (', '.join([k for k in settings.keys() if not settings[k]])),
            level=DEBUG)
        return

    auth_endpoint = "%s://%s:%s/v2.0" % (auth_protocol, settings['auth_host'],
                                         settings['auth_port'])
    keystone = client.Client(token=settings['admin_token'],
                             endpoint=auth_endpoint)

    # CA
    try:
        try:
            # Kilo and newer
            ca_cert = keystone.certificates.get_ca_certificate()
        except AttributeError:
            # Juno and older
            ca_cert = requests.request('GET', auth_endpoint +
                                       '/certificates/ca').text
    except (ConnectionRefused, requests.exceptions.ConnectionError, Forbidden):
        log("Error connecting to keystone - skipping ca/signing cert setup",
            level=WARNING)
        return

    if ca_cert:
        log("Updating ca cert from keystone", level=DEBUG)
        ca = os.path.join(certs_path, 'ca.pem')
        with open(ca, 'w') as fd:
            fd.write(ca_cert)

        out = subprocess.check_output(['openssl', 'x509', '-in', ca,
                                       '-pubkey'])
        p = subprocess.Popen(['certutil', '-d', certs_path, '-A', '-n', 'ca',
                              '-t', 'TCu,Cu,Tuw'], stdin=subprocess.PIPE)
        p.communicate(out)
    else:
        log("No ca cert available from keystone", level=DEBUG)

    # Signing cert
    try:
        try:
            # Kilo and newer
            signing_cert = keystone.certificates.get_signing_certificate()
        except AttributeError:
            # Juno and older
            signing_cert = requests.request('GET', auth_endpoint +
                                            '/certificates/signing').text
    except (ConnectionRefused, requests.exceptions.ConnectionError):
        log("Error connecting to keystone - skipping ca/signing cert setup",
            level=WARNING)
        return

    if signing_cert:
        log("Updating signing cert from keystone", level=DEBUG)
        signing_cert_path = os.path.join(certs_path, 'signing_certificate.pem')
        with open(signing_cert_path, 'w') as fd:
            fd.write(signing_cert)

        out = subprocess.check_output(['openssl', 'x509', '-in',
                                       signing_cert_path, '-pubkey'])
        p = subprocess.Popen(['certutil', '-A', '-d', certs_path, '-n',
                              'signing_cert', '-t', 'P,P,P'],
                             stdin=subprocess.PIPE)
        p.communicate(out)
    else:
        log("No signing cert available from keystone", level=DEBUG)


@hooks.hook('upgrade-charm',
            'config-changed')
@restart_on_change({'/etc/ceph/ceph.conf': ['radosgw'],
                    '/etc/haproxy/haproxy.cfg': ['haproxy']})
@harden()
def config_changed():
    install_packages()

    if config('prefer-ipv6'):
        status_set('maintenance', 'configuring ipv6')
        setup_ipv6()

    for r_id in relation_ids('identity-service'):
        identity_changed(relid=r_id)

    for r_id in relation_ids('cluster'):
        cluster_joined(rid=r_id)

    CONFIGS.write_all()

    if not config('use-embedded-webserver'):
        try:
            subprocess.check_call(['a2ensite', 'rgw'])
        except subprocess.CalledProcessError as e:
            log("Error enabling apache module 'rgw' - %s" % e, level=WARNING)

        # Ensure started but do a soft reload
        subprocess.call(['service', 'apache2', 'start'])
        subprocess.call(['service', 'apache2', 'reload'])
    update_nrpe_config()


@hooks.hook('mon-relation-departed',
            'mon-relation-changed')
@restart_on_change({'/etc/ceph/ceph.conf': ['radosgw']})
def mon_relation():
    rq = ceph.get_create_rgw_pools_rq(
        prefix=config('pool-prefix'))
    if is_request_complete(rq, relation='mon'):
        log('Broker request complete', level=DEBUG)
        CONFIGS.write_all()
        key = relation_get('radosgw_key')
        if key:
            ceph.import_radosgw_key(key)
            restart()  # TODO figure out a better way todo this
    else:
        send_request_if_needed(rq, relation='mon')


@hooks.hook('gateway-relation-joined')
def gateway_relation():
    relation_set(hostname=unit_get('private-address'),
                 port=config('port'))


def start():
    subprocess.call(['service', 'radosgw', 'start'])
    open_port(port=config('port'))


def stop():
    subprocess.call(['service', 'radosgw', 'stop'])
    open_port(port=config('port'))


def restart():
    subprocess.call(['service', 'radosgw', 'restart'])
    open_port(port=config('port'))


@hooks.hook('identity-service-relation-joined')
def identity_joined(relid=None):
    if cmp_pkgrevno('radosgw', '0.55') < 0:
        log('Integration with keystone requires ceph >= 0.55')
        sys.exit(1)

    port = config('port')
    admin_url = '%s:%i/swift' % (canonical_url(None, ADMIN), port)
    internal_url = '%s:%s/swift/v1' % \
        (canonical_url(None, INTERNAL), port)
    public_url = '%s:%s/swift/v1' % \
        (canonical_url(None, PUBLIC), port)
    relation_set(service='swift',
                 region=config('region'),
                 public_url=public_url, internal_url=internal_url,
                 admin_url=admin_url,
                 requested_roles=config('operator-roles'),
                 relation_id=relid)

    if relid:
        for unit in related_units(relid):
            setup_keystone_certs(unit=unit, rid=relid)
    else:
        setup_keystone_certs()


@hooks.hook('identity-service-relation-changed')
@restart_on_change({'/etc/ceph/ceph.conf': ['radosgw']})
def identity_changed(relid=None):
    identity_joined(relid)
    CONFIGS.write_all()
    restart()


@hooks.hook('cluster-relation-joined')
@restart_on_change({'/etc/haproxy/haproxy.cfg': ['haproxy']})
def cluster_joined(rid=None):
    settings = {}
    if config('prefer-ipv6'):
        private_addr = get_ipv6_addr(exc_list=[config('vip')])[0]
        settings['private-address'] = private_addr

    relation_set(relation_id=rid, **settings)


@hooks.hook('cluster-relation-changed')
@restart_on_change({'/etc/haproxy/haproxy.cfg': ['haproxy']})
def cluster_changed():
    CONFIGS.write_all()
    for r_id in relation_ids('identity-service'):
        identity_joined(relid=r_id)


@hooks.hook('ha-relation-joined')
def ha_relation_joined():
    vip = config('vip')
    if not vip:
        log('Unable to configure hacluster as vip not provided', level=ERROR)
        sys.exit(1)

    # Obtain resources
    resources = {
        'res_cephrg_haproxy': 'lsb:haproxy'
    }
    resource_params = {
        'res_cephrg_haproxy': 'op monitor interval="5s"'
    }

    vip_group = []
    for vip in vip.split():
        if is_ipv6(vip):
            res_rgw_vip = 'ocf:heartbeat:IPv6addr'
            vip_params = 'ipv6addr'
        else:
            res_rgw_vip = 'ocf:heartbeat:IPaddr2'
            vip_params = 'ip'

        iface = get_iface_for_address(vip)
        netmask = get_netmask_for_address(vip)

        if iface is not None:
            vip_key = 'res_cephrg_{}_vip'.format(iface)
            resources[vip_key] = res_rgw_vip
            resource_params[vip_key] = (
                'params {ip}="{vip}" cidr_netmask="{netmask}"'
                ' nic="{iface}"'.format(ip=vip_params,
                                        vip=vip,
                                        iface=iface,
                                        netmask=netmask)
            )
            vip_group.append(vip_key)

    if len(vip_group) >= 1:
        relation_set(groups={CEPHRG_HA_RES: ' '.join(vip_group)})

    init_services = {
        'res_cephrg_haproxy': 'haproxy'
    }
    clones = {
        'cl_cephrg_haproxy': 'res_cephrg_haproxy'
    }

    # Obtain the config values necessary for the cluster config. These
    # include multicast port and interface to bind to.
    corosync_bindiface = config('ha-bindiface')
    corosync_mcastport = config('ha-mcastport')

    relation_set(init_services=init_services,
                 corosync_bindiface=corosync_bindiface,
                 corosync_mcastport=corosync_mcastport,
                 resources=resources,
                 resource_params=resource_params,
                 clones=clones)


@hooks.hook('ha-relation-changed')
def ha_relation_changed():
    clustered = relation_get('clustered')
    if clustered:
        log('Cluster configured, notifying other services and'
            'updating keystone endpoint configuration')
        # Tell all related services to start using
        # the VIP instead
        for r_id in relation_ids('identity-service'):
            identity_joined(relid=r_id)


@hooks.hook('nrpe-external-master-relation-joined',
            'nrpe-external-master-relation-changed')
def update_nrpe_config():
    # python-dbus is used by check_upstart_job
    apt_install('python-dbus')
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.copy_nrpe_checks()
    nrpe.add_init_service_checks(nrpe_setup, services(), current_unit)
    nrpe.add_haproxy_checks(nrpe_setup, current_unit)
    nrpe_setup.write()


@hooks.hook('update-status')
@harden()
def update_status():
    log('Updating status.')


if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    set_os_workload_status(CONFIGS, REQUIRED_INTERFACES,
                           charm_func=check_optional_relations)
