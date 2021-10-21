#![allow(dead_code)]
use nix::errno::Errno;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use nix::unistd::pipe;

pub struct TempDir {
    name: PathBuf,
    write_to_clean_up: i32,
}

impl TempDir {
    pub fn path(&self) -> &Path {
        self.name.as_ref()
    }
}

pub fn tempdir() -> nix::Result<TempDir> {
    let mut template = env::temp_dir();
    template.push("containerized-shell.XXXXXX");
    let mut bytes = template.into_os_string().into_vec();
    // null byte
    bytes.push(0);
    let res = unsafe { libc::mkdtemp(bytes.as_mut_ptr().cast()) };
    if res.is_null() {
        Err(nix::Error::Sys(Errno::last()))
    } else {
        // remove null byte
        bytes.pop();
        let name = PathBuf::from(OsString::from_vec(bytes));

        // The problem: When we drop, we might have chroot-ed somewhere. Therefore, deleting this
        // temp-folder failes. What we need to do, is have a process remaining in the original
        // namespace and root-dir. This is what we create here. It's stupid, I know. But I don't
        // like deleting somewhat large folders in /tmp manually. Or, FWIW, reboot.
        let (read_end, write_to_clean_up) = pipe()?;
        if let nix::unistd::ForkResult::Child = unsafe { nix::unistd::fork()? } {
            let mut buf = [0u8; 1];
            let _ = nix::unistd::read(read_end, &mut buf);
            let _ = fs::remove_dir_all(name);
            std::process::exit(0);
        }
        Ok(TempDir {
            name,
            write_to_clean_up,
        })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = nix::unistd::write(self.write_to_clean_up, &[0u8; 1]);
    }
}
