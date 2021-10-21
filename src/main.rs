mod ifreq;
mod tmp;

use libc::{setdomainname, getmntent, endmntent, setmntent};
use nix::ioctl_read_bad;
use nix::errno::Errno;
use nix::Error;
use nix::mount::{mount, MsFlags};
use nix::net::if_::InterfaceFlags;
use nix::sched::{unshare, CloneFlags};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use nix::sys::stat::{fchmodat, FchmodatFlags, Mode};
use nix::sys::wait::{waitpid, WaitPidFlag};
use nix::unistd::{
    chdir, chroot, close, execvp, fork, getgid, getpid, getuid, setgid, sethostname, setuid,
    symlinkat, ForkResult, Gid, Uid,
};
use std::env;
use std::ffi::{CString, CStr};
use std::fs::{create_dir, File, OpenOptions};
use std::io::{prelude::Write, BufRead, BufReader, ErrorKind};
use std::path::PathBuf;
use std::process::exit;

use anyhow::{anyhow, Result, Context};

type R<T = ()> = Result<T>;

fn main() -> R {
    let args: Vec<_> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: {} <base-dir> <cgroup-name> <cmd>\n",
            env::current_exe()
                .unwrap_or_else(|_| PathBuf::from(""))
                .display()
        );
        eprintln!("<base-dir> is the path to the folder that contains a template of the new root.\n\
                  \tThis will be copied to a tmp-folder for each shell.");
        eprintln!("<cgroup-name> is the name of the cgroup to add the shell to.\n\
                  \tThis name should be a full path relative from the cgroup base directory.\n\
                  \tPlease note that the group has to be configured manually, as it requires host \
                  root privileges.");
        eprintln!("<cmd> is the command to execute inside the container, usually a shell like bash.");
        exit(1);
    }

    let parent_uid = getuid();
    let parent_gid = getgid();

    // we need to prepare the chroot directory before we unshare
    let tmp_dir = prepare_chroot_dir(&args[1])
        .with_context(|| "Could not prepare folder to chroot into")?;

    setup_cgroups(&args[2]).with_context(|| "Could not setup CGroups")?;

    unshare(
        CloneFlags::CLONE_FS // unshare chroot
            | CloneFlags::CLONE_NEWIPC
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWNET
            | CloneFlags::CLONE_NEWNS // unshare mount namespace
            | CloneFlags::CLONE_NEWUSER,
    ).with_context(|| "could not unshare")?;

    setup_user_ns(parent_uid, parent_gid).with_context(|| {
        format!("Could not setup user namespace to map to U/G {}/{}",
                parent_uid, parent_gid)
    })?;
    setup_uts_ns().with_context(|| "Could not setup UTS namespace")?;
    setup_network_ns().with_context(|| "Could not setup network namespace")?;

    match unsafe { fork() }.with_context(|| "Error while forking")? {
        ForkResult::Parent { child: child_pid } => {
            waitpid(child_pid, Some(WaitPidFlag::WSTOPPED))
                .with_context(|| format!("Error while waiting for pid {}", child_pid))?;
        }
        ForkResult::Child => {
            // We need all capabilities for setup_mount_ns. Thus it must happen in the new process.
            setup_mount_ns(&tmp_dir).with_context(|| {
                format!("Error while creating mount namespace in {:?}", tmp_dir.path())
            })?;
            exec_command(&args).with_context(|| "Error while trying to execute the command")?;
        }
    }
    Ok(())
}

fn setup_user_ns(parent_uid: Uid, parent_gid: Gid) -> R {
    writeln!(
        OpenOptions::new()
            .write(true)
            .open("/proc/self/setgroups")
            .with_context(|| "Could not open /proc/self/setgroups")?,
        "deny"
    ).with_context(|| "Could not write \"deny\" to /proc/self/setgroups")?;

    // use format! to force only a single write operation
    write!(
        OpenOptions::new()
            .append(true)
            .open("/proc/self/uid_map")
            .with_context(|| "Could not open /proc/self/uid_map")?,
        "{}",
        format!("1000 {} 1", parent_uid)
    ).with_context(|| format!("Could not write \"1000 {} 1\" to /proc/self/uid_map", parent_uid))?;
    write!(
        OpenOptions::new()
            .append(true)
            .open("/proc/self/gid_map")
            .with_context(|| "Could not open /proc/self/gid_map")?,
        "{}",
        format!("1000 {} 1", parent_gid)
    ).with_context(|| format!("Could not write \"1000 {} 1\" to /proc/self/gid_map", parent_gid))?;

    setuid(Uid::from_raw(1000)).with_context(|| "Could not set UID to 1000")?;
    setgid(Gid::from_raw(1000)).with_context(|| "Could not set GID to 1000")?;

    Ok(())
}

fn setup_uts_ns() -> R {
    sethostname("localhost").with_context(|| "Could not set the hostname to \"localhost\"")?;
    const DOMAINNAME: &[u8] = b"(none)";
    unsafe {
        setdomainname(DOMAINNAME.as_ptr() as _, DOMAINNAME.len());
    }
    Ok(())
}

fn setup_network_ns() -> R {
    // bring loopback device UP
    const SIOCSSIFFLAGS: u32 = 0x8914;
    ioctl_read_bad!(socket_set_interface_flags, SIOCSSIFFLAGS, ifreq::ifreq);

    let sock = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    ).with_context(|| "Could not create Socket (IP, Datagram, SOCK_CLOEXEC, None)")?;
    let mut if_name = [0u8; 16];
    if_name[..2].copy_from_slice(b"lo");
    let mut req = ifreq::ifreq {
        ifr_name: if_name,
        ifr_ifru: ifreq::ifr_ifru {
            ifr_flags: (InterfaceFlags::IFF_UP
                    | InterfaceFlags::IFF_LOOPBACK
                    | InterfaceFlags::IFF_RUNNING)
                .bits() as _,
        },
    };
    unsafe { socket_set_interface_flags(sock, &mut req) }
        .with_context(|| "Could not setup the Interface (ioctl failed)")?;
    close(sock).with_context(|| "Could not close the socket - WHAT?")?;
    Ok(())
}

fn prepare_chroot_dir(build_dir: &str) -> R<tmp::TempDir> {
    let tmp_dir = tmp::tempdir().with_context(|| "Could not create a tempdir")?;

    // recursive copy of the build directory
    let mut copy_cmd = "cp -ar '".to_string();
    copy_cmd += build_dir.replace("'", "\\'").as_str(); // FIXME super safe injection protection
    copy_cmd += "/.' '";
    copy_cmd += tmp_dir.path().to_str().unwrap();
    copy_cmd += "' 2>/dev/null >/dev/null";

    let copy_cmd = CString::new(copy_cmd).with_context(|| "Could not create CString")?;
    unsafe { libc::system(copy_cmd.as_ptr()) };

    for d in &[ "bin", "etc", "proc", "tmp", "dev", "dev/pts", "dev/shm", "home", "home/user"] {
        create_dir(tmp_dir.path().join(d)).or_else(|error| {
            // ignore if a folder already exists
            if error.kind() == ErrorKind::AlreadyExists { Ok(()) } else { Err(error) }
        }).with_context(|| format!("Could not create dir {:?}", tmp_dir.path().join(d)))?;
    }
    for f in &[
        "dev/full",
        "dev/kvm",
        "dev/null",
        "dev/ptmx",
        "dev/random",
        "dev/tty",
        "dev/urandom",
        "dev/zero",
    ] {
        File::create(tmp_dir.path().join(f))
            .with_context(|| format!("Could not create file {:?}", tmp_dir.path().join(f)))?;
    }

    for (from, to) in ["", "/0", "/1", "/2"]
        .iter()
        .map(|i| format!("/proc/self/fd{}", i))
        .zip(
            ["fd", "stdin", "stdout", "stderr"]
                .iter()
                .map(|s| tmp_dir.path().join(format!("dev/{}", s))),
        )
    {
        symlinkat(from.as_str(), None, &to)
            .with_context(|| format!("Could not create symlink from {:?} to {:?}", from, to))?;
    }

    writeln!(
        OpenOptions::new()
            .write(true)
            .create(true)
            .open(tmp_dir.path().join("etc").join("group"))
            .with_context(|| {
                format!("Could not open file \"{:?}\" to write",
                        tmp_dir.path().join("etc").join("group"))
            })?,
        "root:x:0:\n\
         user:!:1000:\n\
         nogroup:x:65534:"
    ).with_context(|| {
        format!("Could not write into \"{:?}\"", tmp_dir.path().join("etc").join("group"))
    })?;

    writeln!(
        OpenOptions::new()
            .write(true)
            .create(true)
            .open(tmp_dir.path().join("etc").join("passwd"))
            .with_context(|| {
                format!("Could not open file \"{:?}\" to write",
                        tmp_dir.path().join("etc").join("passwd"))
            })?,
        "root:x:0:0:Superuser:/root:/noshell\n\
         user:x:1000:1000:Container user:/home/user:/bin/bash\n\
         nobody:x:65534:65534:Nobody:/:/noshell"
    ).with_context(|| format!("Could not write into \"{:?}\"",
                              tmp_dir.path().join("etc").join("passwd")))?;

    writeln!(
        OpenOptions::new()
            .write(true)
            .create(true)
            .open(tmp_dir.path().join("etc").join("hosts"))
            .with_context(|| format!("Could not open file \"{:?}\" to write",
                                     tmp_dir.path().join("etc").join("hosts")))?,
        "127.0.0.1 localhost\n\
         ::1 localhost"
    ).with_context(|| format!("Could not write into \"{:?}\"",
                              tmp_dir.path().join("etc").join("hosts")))?;
    fchmodat(
        None,
        &tmp_dir.path().join("tmp"),
        Mode::from_bits(0o0777).unwrap(),
        FchmodatFlags::FollowSymlink,
    ).with_context(|| format!("Could not chmod 0777 {:?}", tmp_dir.path().join("tmp")))?;
    Ok(tmp_dir)
}

fn setup_mount_ns(tmp_dir: &tmp::TempDir) -> R {
    mount::<_, _, str, str>(
        Some("."),
        ".",
        None,
        MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None,
    ).with_context(|| "Could not bind-mount . to .")?;
    for path in &[
        "/dev/full",
        "/dev/kvm",
        "/dev/null",
        "/dev/ptmx",
        "/dev/random",
        "/dev/tty",
        "/dev/urandom",
        "/dev/zero",
        "/dev/pts",
    ] {
        mount::<_, _, str, str>(
            Some(*path),
            &tmp_dir.path().join(&path[1..]),
            None,
            MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None,
        ).with_context(|| format!("Could not bind-mount {:?} into the same folder in {:?}",
                                  path, tmp_dir.path()))?;
    }
    for (target, fs_type) in &[("proc", "proc"), ("dev/shm", "tmpfs"), ("tmp", "tmpfs")] {
        mount::<str, _, _, str>(
            None,
            &tmp_dir.path().join(*target),
            Some(*fs_type),
            MsFlags::empty(),
            None,
        ).with_context(|| format!("Could not mount None to {:?}, type {}",
                                  tmp_dir.path().join(*target), fs_type))?;
    }

    chdir(tmp_dir.path())
        .with_context(|| format!("Could not chdir into \"{:?}\"", tmp_dir.path()))?;
    chroot(tmp_dir.path())
        .with_context(|| format!("Could not chroot into \"{:?}\"", tmp_dir.path()))?;

    Ok(())
}

fn setup_cgroups(group_name: &str) -> R {
    let p;
    unsafe {
        // find cgroups2 mount point
        let f = setmntent(
            CString::new("/etc/mtab")
                .with_context(|| "Could not create CString")?
                .as_ptr(),
            CString::new("r").with_context(|| "Could not create CString")?.as_ptr(),
        );
        if f.is_null() {
            return Err(anyhow!(Error::Sys(Errno::last())));
        }
        if let Some(mnt) = loop {
            let mnt = getmntent(f);
            if mnt.is_null() {
                break None;
            }
            if CStr::from_ptr((*mnt).mnt_type).to_bytes() == &b"cgroup2"[..] {
                break Some(mnt);
            }
        } {
            p = PathBuf::from(
                CStr::from_ptr((*mnt).mnt_dir)
                    .to_str()
                    .with_context(|| "CGroups2-Mountpoint was not valid UTF-8")?,
            );
        } else {
            return Err(anyhow!("No CGroups2 Mountpoint was found!"));
        }
        endmntent(f);
    }
    let p = p.join(group_name);
    if !p.exists() {
        eprintln!("CGroup \"{}\" does not exist!\n\
                    Make sure that it exists and create it if necessary.", group_name);
        return Err(anyhow!(Error::Sys(Errno::last())));
    }
    let mut s = String::new();
    BufReader::new(File::open("/proc/self/cgroup")
                            .with_context(|| "Could not open\"/proc/self/cgroup\"")?)
        .read_line(&mut s)
        .with_context(|| "Could not read the first line from \"/proc/self/cgroup\"")?;
    write!(
        OpenOptions::new()
            .write(true)
            .open(p.join("cgroup.procs"))
            .with_context(|| format!("Could not open {:?}", p.join("cgroup.procs")))?,
        "{}",
        format!("{}\n", getpid())
    ).with_context(|| {
        format!("Could not write pid \"{}\" to {:?}",
                getpid(), p.join("cgroup.procs"))
    })?;
    Ok(())
}

fn exec_command(args: &Vec<String>) -> R {
    let x = &args[3..].iter().map(|c| CString::new(&c[..]).unwrap()).collect::<Vec<_>>()[..];
    execvp(
        CString::new(args[3].clone()).with_context(|| "Could not make CString")?.as_c_str(),
        &x.iter().map(|cs| cs.as_c_str()).collect::<Vec<_>>()[..],
    )?;
    unreachable!();
}
