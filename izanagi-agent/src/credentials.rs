//! Resolve identities before fork and discard inherited supplementary groups.

pub(crate) fn lookup_user(
    user: &str,
) -> anyhow::Result<Option<(libc::uid_t, libc::gid_t, String)>> {
    // getpwnam_r is thread-safe; no passwd pointer crosses an await or a fork.
    let c_user =
        std::ffi::CString::new(user).map_err(|_| anyhow::anyhow!("invalid execution user"))?;
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut buf_size: usize = 1024;
    let mut found = None;
    loop {
        let mut buf = vec![0u8; buf_size];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let ret = unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                &mut entry,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if ret == 0 && !result.is_null() {
            let home = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }
                .to_str()
                .unwrap_or("/home/izanagi")
                .to_owned();
            found = Some((entry.pw_uid, entry.pw_gid, home));
            break;
        } else if ret == libc::ERANGE && buf_size < 1_048_576 {
            buf_size *= 2;
            continue;
        } else if ret != 0 {
            return Err(std::io::Error::from_raw_os_error(ret).into());
        } else {
            break;
        }
    }
    Ok(found)
}

/// Post-fork: async-signal-safe calls only. Never exec after a failed transition.
pub(crate) unsafe fn drop_identity(uid: libc::uid_t, gid: libc::gid_t) -> std::io::Result<()> {
    unsafe {
        // On Linux bypass libc's thread-wide credential coordination after fork.
        // Only this single-threaded child must lose its supplementary groups.
        #[cfg(target_os = "linux")]
        let groups_result =
            libc::syscall(libc::SYS_setgroups, 0usize, std::ptr::null::<libc::gid_t>());
        #[cfg(not(target_os = "linux"))]
        let groups_result = libc::setgroups(0, std::ptr::null());
        if groups_result != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn lookup_rejects_nul_and_distinguishes_missing_users() {
        assert!(super::lookup_user("invalid\0user").is_err());
        assert!(
            super::lookup_user("izanagi-no-such-user-regression-67")
                .unwrap()
                .is_none()
        );
    }
}
