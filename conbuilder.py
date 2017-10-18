#!/usr/bin/env python3
#
# Copyright 2017 Federico Ceratto <federico@debian.org>
# Released under GPLv3 License, see LICENSE file

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from configparser import ConfigParser
from glob import glob
from shutil import copy2
from subprocess import Popen, PIPE
import hashlib
import os
import os.path


default_conf = """
[DEFAULT]
config_version = 1

# where all the layers are stored
cachedir = /var/cache/conbuilder

# where to copy the generated .deb .changes .dsc ... files
export_dir = ../build-area/

tarball_dir = ../tarballs/

# one or more capabilities to drop during the build.
# L1 and L2 creation is not affected.
# see man systemd-nspawn
# drop_capability =
#
# Some capabilities that can be disabled with most builds:
# drop_capability = CAP_CHOWN,CAP_DAC_READ_SEARCH,CAP_FOWNER,CAP_FSETID,CAP_IPC_OWNER,CAP_KILL,CAP_LEASE,CAP_LINUX_IMMUTABLE,CAP_NET_BIND_SERVICE,CAP_NET_BROADCAST,CAP_NET_RAW,CAP_SETGID,CAP_SETFCAP,CAP_SETPCAP,CAP_SETUID,CAP_SYS_ADMIN,CAP_SYS_CHROOT,CAP_SYS_NICE,CAP_SYS_PTRACE,CAP_SYS_TTY_CONFIG,CAP_SYS_RESOURCE,CAP_SYS_BOOT,CAP_AUDIT_WRITE,CAP_AUDIT_CONTROL

# one or more capabilities to drop during the build.
# L1 and L2 creation is not affected.
# see man systemd-nspawn
system_call_filter = ""

# purge layer 2 trees older than:
l2_max_age_days = 30

# *also* purge older layers 2 if there are more than:
l2_max_number = 10
"""

help_msg = """
Build Debian packages using overlay FS and systemd namespace containers
conbuilder creates a base filesystem using debootstrap, then
overlays it with a filesystem to install the required dependencies
and finally runs the build on another overlay.

Layers are created, reused and purged automatically to achieve
fast package builds while minimizing disk usage.
conbuilder also allows you to selectively disable networking,
system calls and capabilities.

show:
    show running containers, filesystem layers and overlay mounts

create:
    create new base system using debootstrap.
    Use --codename to pick sid, wheezy etc..

    $ conbuilder create --codename wheezy

update:
    update base system using debootstrap

    $ conbuilder update --codename wheezy

build:
    build package using dpkg-buildpackage
    Creates an overlay called L2 if not already available.
    Options after '--' will be passed to dpkg-buildpackage

Default configuration:
--
{conf}
--

""".format(conf=default_conf)


def run(cmd, quietcmd=False, quiet=False):
    """Run command, capture output
    """
    assert isinstance(cmd, str), repr(cmd)
    if not quietcmd:
        print(cmd)
    proc = Popen(cmd, shell=True, stdout=PIPE)
    out = []
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        line = line.rstrip().decode()
        out.append(line)
        if not quiet:
            print(line)

    proc.wait()
    if proc.returncode != 0:
        raise Exception("'{}' returned {}".format(cmd, proc.returncode))

    return out


def mount(lower, upper, work, mnt):
    cmd = "sudo mount -t overlay overlay " \
        "-olowerdir={},upperdir={},workdir={} {}"
    cmd = cmd.format(lower, upper, work, mnt)
    run(cmd)
    assert os.path.isfile(os.path.join(mnt, "usr/bin/apt"))


def umount(path):
    run("sudo umount {}".format(path))


def nspawn(rcmd, quiet=False, drop_capability='', system_call_filter=''):
    assert isinstance(rcmd, str)
    cmd = "sudo systemd-nspawn -M conbuilder --chdir=/srv "
    if drop_capability:
        cmd += "--drop-capability={} ".format(drop_capability)
    if system_call_filter:
        cmd += "--system-call-filter={} ".format(system_call_filter)
    cmd += rcmd
    return run(cmd, quiet=quiet)


def _parse_build_deps(out):
    """Parse build deps from apt-get build-dep
    """
    deps = set()
    for line in out:
        if not line.startswith("Inst "):
            continue
        # Example: Inst gettext (0.19.8.1-4 Debian:unstable [amd64]) []
        _, pkgname, version, _1 = line.split(' ', 3)
        assert version.startswith('('), "Cannot parse version from %r" % line
        version = version[1:]
        assert version, "Cannot parse version from %r" % line
        deps.add((pkgname, version))

    deps = sorted(deps)
    return deps


def extract_build_dependencies():
    """Run apt-get build-deps in simulated mode on a read-only FS that
    contains only the base system and the pkg sources

    :returns: ([('pkgname', 'version'), ... ], 'fingerprint')
    """
    cmd = "-D /home/fede/conbuilder/l1/sid/ --read-only " \
        "--overlay=$(pwd)::/srv  -- /usr/bin/apt-get build-dep -s ."
    out = nspawn(cmd, quiet=True)
    deps = _parse_build_deps(out)

    # generate deterministic fingerprint
    block = (str(sorted(deps))).encode()
    fprint = hashlib.sha224(block).hexdigest()[:10]
    return (deps, fprint)


def load_conf_and_parse_args():
    confighome = os.path.expanduser(
        os.environ.get('XDG_CONFIG_HOME', '~/.config'))
    default_conf_fn = os.path.join(confighome, 'conbuilder.conf')

    ap = ArgumentParser(epilog=help_msg,
                        formatter_class=RawDescriptionHelpFormatter)
    ap.add_argument(
        '--conf', default=default_conf_fn,
        help="Config file path (default: {})".format(default_conf_fn)
    )
    ap.add_argument('action', choices=[
        'create', 'update', 'build', 'purge', 'show'
    ])
    ap.add_argument('--codename', default='sid', help='codename (default: sid)')
    ap.add_argument('--verbose', '-v', action='count', default=0,
                    help='increase verbosity up to 3 times')
    ap.add_argument("extra_args", nargs="*")  # for dpkg-buildpackage
    args = ap.parse_args()
    if args.extra_args and args.action != "build":
        ap.error("Extra arguments should be passed only during build")

    # generate default conf file if needed
    if args.conf == default_conf_fn and not os.path.isfile(args.conf):
        print("Configuration file not found. Generating {}".format(args.conf))
        with open(args.conf, 'w') as f:
            f.write(default_conf)

    cp = ConfigParser()
    with open(args.conf) as f:
        cp.read_file(f)
    args.cachedir = cp['DEFAULT']['cachedir']
    assert args.cachedir not in ('', '/'), "Invalid cache dir"
    args.export_dir = cp['DEFAULT']['export_dir']

    drop_capability = cp['DEFAULT'].get('drop_capability', '')
    args.drop_capability = drop_capability.strip().replace(', ', ',')
    args.system_call_filter = cp['DEFAULT'].get('system_call_filter', '')
    return args


def create_l1(conf, l1dir):
    """Run debootstrap to create the L1 FS
    """
    print("Creating", l1dir)
    os.makedirs(l1dir)
    cmd = "sudo debootstrap --include=apt --keyring=/etc/apt/trusted.gpg" \
        " --force-check-gpg {} {} http://httpredir.debian.org/debian"
    cmd = cmd.format(conf.codename, l1dir)
    run(cmd)
    assert os.path.isfile(os.path.join(l1dir, "usr/bin/apt"))
    assert os.path.isdir(os.path.join(l1dir, "etc")), \
        "/etc not found in {} ".format(l1dir)


def update_l1(conf, l1dir):
    """Update the L1 FS
    """
    # TODO invalidate L2s
    print("Updating", l1dir)
    nspawn("-D {} -- /usr/bin/apt-get -y update".format(l1dir))
    nspawn("-D {} -- /usr/bin/apt-get -y dist-upgrade".format(l1dir))


def create_l2(conf, l1dir, l2dir, l2workdir, l2mountdir, expected_deps):
    """Run apt-get build-deps in the L2 FS to install dependencies
    """
    print("[L2] Creating", l2dir)
    os.makedirs(l2dir)
    os.makedirs(l2workdir)
    os.makedirs(l2mountdir)
    try:
        mount(l1dir, l2dir, l2workdir, l2mountdir)

        deps_list = ["{}:{}".format(name, ver) for name, ver in expected_deps]
        print("[L2] Installing dependencies...")
        if conf.verbose == 0:
            print("[L2]", " ".join(deps_list))

        cmd = "-D {} --overlay=$(pwd)::/srv  -- /usr/bin/apt-get build-dep -y ."
        cmd = cmd.format(l2mountdir)
        out = nspawn(cmd, quiet=(conf.verbose == 0))
        _parse_build_deps(out)
        cmd = "-D {} --overlay=$(pwd)::/srv  -- /usr/bin/apt-get clean"
        with open(os.path.join(l2mountdir, '.deps.conbuilder'), 'w') as f:
            f.write("\n".join(deps_list))

    finally:
        umount(l2mountdir)


def build(conf):
    """Run a package build
    """
    success = False

    # L1: base system
    l1dir = os.path.join(conf.cachedir, "l1", conf.codename)
    if not os.path.exists(l1dir):
        create_l1(conf, l1dir)

    # L2: build dependencies

    deps, dep_hash = extract_build_dependencies()

    l2dir = os.path.join(conf.cachedir, "l2", "fs", dep_hash)
    l2workdir = os.path.join(conf.cachedir, "l2", "overlay_work", dep_hash)
    l2mountdir = os.path.join(conf.cachedir, "l2", "overlay_mount", dep_hash)
    print("[L1] Ready")

    if not os.path.exists(l2dir):
        create_l2(conf, l1dir, l2dir, l2workdir, l2mountdir, deps)

    try:
        mount(l1dir, l2dir, l2workdir, l2mountdir)
        print("[L2] Ready")

        l3dir = os.path.join(conf.cachedir, "l3", "fs", dep_hash)
        l3workdir = os.path.join(conf.cachedir, "l3", "overlay_work", dep_hash)
        l3mountdir = os.path.join(conf.cachedir, "l3", "overlay_mount",
                                  dep_hash)
        if not os.path.exists(l3dir):
            print("[L3] Creating", l3dir)
            os.makedirs(l3dir)
            os.makedirs(l3workdir)
            os.makedirs(l3mountdir)
        try:
            mount(l2mountdir, l3dir, l3workdir, l3mountdir)
            run("sudo cp -a . {}".format(os.path.join(l3mountdir, "srv")))
            # TODO: configurable --private-network
            cmd = "--private-network -D {} -- /usr/bin/dpkg-buildpackage {}"
            cmd = cmd.format(l3mountdir, " ".join(conf.extra_args))
            nspawn(
                cmd,
                drop_capability=conf.drop_capability,
                system_call_filter=conf.system_call_filter
            )
            success = True

        finally:
            umount(l3mountdir)

    finally:
        umount(l2mountdir)

    if not success:
        return

    if conf.export_dir:
        dest = os.path.abspath(conf.export_dir)
        exts = ("deb", "changes", "xz", "gz", "buildinfo", "dsc")
        for e in exts:
            cmd = "cp -a {}/*.{} {}/ || true".format(l3dir, e, dest)
            run(cmd)

        print("\n[Success]")

    else:
        print("\n[Success] Output is at {}".format(l3dir))




def show(conf):
    print("Mounted overlays:")
    run("mount | grep ^overlay | cat", quietcmd=True)

    print("Running containers:")
    run("machinectl list | grep conbuilder | cat", quietcmd=True)

    print("Layers:")
    for nick, path in (('L1', 'l1'), ('L2', 'l2/fs'), ('L3', 'l3/fs')):
        print("  {}:".format(nick))
        for item in os.scandir(os.path.join(conf.cachedir, path)):
            size = run("sudo du -hs {}".format(item.path),
                       quietcmd=True, quiet=True)
            size = size[0].split('\t')[0]
            print("    {:35} {}".format(item.name, size))
            deps_fn = os.path.join(item.path, '.deps.conbuilder')
            if not os.path.isfile(deps_fn):
                continue
            with open(deps_fn) as f:
                for line in f:
                    print("     ", line.rstrip())
            # TODO add age
            print()
        print()


def main():
    conf = load_conf_and_parse_args()

    if conf.action == 'create':
        l1dir = os.path.join(conf.cachedir, "l1", conf.codename)
        create_l1(conf, l1dir)

    elif conf.action == 'update':
        l1dir = os.path.join(conf.cachedir, "l1", conf.codename)
        update_l1(conf, l1dir)

    if conf.action == 'build':
        build(conf)

    elif conf.action == 'purge':
        # TODO
        raise NotImplementedError

    elif conf.action == 'show':
        show(conf)



if __name__ == '__main__':
    main()
