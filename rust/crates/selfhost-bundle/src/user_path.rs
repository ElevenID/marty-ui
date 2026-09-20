//! pathlib-compatible tilde selection. Expansion never writes or resolves paths;
//! the package owner's root/traversal/symlink checks still run afterward.
use marty_selfhost_bundle::Result;
use std::{
    ffi::{OsStr, OsString},
    path::{Component, PathBuf},
};

fn username(first: &OsStr) -> Option<OsString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        first
            .as_bytes()
            .strip_prefix(b"~")
            .map(|name| OsString::from_vec(name.to_vec()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let wide: Vec<_> = first.encode_wide().collect();
        wide.strip_prefix(&[b'~' as u16]).map(OsString::from_wide)
    }
}

fn expand_with(
    path: PathBuf,
    select: impl FnOnce(&OsStr) -> Result<Option<PathBuf>>,
) -> Result<PathBuf> {
    let mut parts = path
        .components()
        .filter(|part| !matches!(part, Component::CurDir));
    let Some(Component::Normal(first)) = parts.next() else {
        return Ok(path);
    };
    let Some(name) = username(first) else {
        return Ok(path
            .components()
            .filter(|part| !matches!(part, Component::CurDir))
            .collect());
    };
    let mut home = select(&name)?.ok_or("Could not determine home directory.")?;
    for part in parts {
        home.push(part);
    }
    Ok(home)
}

#[cfg(windows)]
fn windows_home(name: &OsStr, env: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let mut home = env("USERPROFILE").map(PathBuf::from).or_else(|| {
        let path = env("HOMEPATH")?;
        Some(PathBuf::from(env("HOMEDRIVE").unwrap_or_default()).join(path))
    })?;
    if !name.is_empty() && env("USERNAME").as_deref() != Some(name) {
        let current = env("USERNAME")?;
        // ntpath.basename intentionally does not strip a trailing separator.
        if home.as_os_str().to_string_lossy().ends_with(['/', '\\'])
            || home.file_name().unwrap_or(OsStr::new("")) != current
        {
            return None;
        }
        home = home.parent().unwrap_or(&home).join(name);
    }
    Some(home)
}

#[cfg(unix)]
fn posix_home(
    name: &OsStr,
    home: Option<OsString>,
    lookup: impl FnOnce(Option<&OsStr>) -> Result<Option<PathBuf>>,
) -> Result<Option<PathBuf>> {
    let selected = if name.is_empty() {
        match home {
            Some(home) => Some(PathBuf::from(home)),
            None => lookup(None)?,
        }
    } else {
        lookup(Some(name))?
    };
    // posixpath.expanduser('~') converts empty/all-slash HOME to '/'.
    Ok(selected.map(|path| {
        if path.as_os_str().is_empty() {
            PathBuf::from("/")
        } else {
            path
        }
    }))
}

pub fn expand(path: PathBuf) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        expand_with(path, |name| {
            Ok(windows_home(name, |key| std::env::var_os(key)))
        })
    }
    #[cfg(unix)]
    {
        expand_with(path, |name| {
            posix_home(name, std::env::var_os("HOME"), account_home)
        })
    }
}

pub fn archive(path: PathBuf) -> Result<PathBuf> {
    let expanded: PathBuf = expand(path)?
        .components()
        .filter(|part| !matches!(part, Component::CurDir))
        .collect();
    let mut expanded = expanded.into_os_string();
    expanded.push(".zip");
    Ok(PathBuf::from(expanded))
}

#[cfg(unix)]
fn account_home(name: Option<&OsStr>) -> Result<Option<PathBuf>> {
    use std::{
        ffi::{CStr, CString},
        os::unix::ffi::{OsStrExt, OsStringExt},
    };
    let name = name
        .map(|name| CString::new(name.as_bytes()).map_err(|_| "Account name contains NUL"))
        .transpose()?;
    let mut capacity = 1024usize;
    loop {
        let mut buffer = vec![0u8; capacity];
        let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: reentrant NSS functions receive caller-owned, live buffers
        // and record/result pointers. No fields are read unless rc=0 and found
        // is non-null. pw_dir is copied before either allocation is released.
        let code = unsafe {
            match &name {
                Some(name) => libc::getpwnam_r(
                    name.as_ptr(),
                    record.as_mut_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut found,
                ),
                None => libc::getpwuid_r(
                    libc::getuid(),
                    record.as_mut_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut found,
                ),
            }
        };
        if code == libc::ERANGE && capacity < 1024 * 1024 {
            capacity *= 2;
            continue;
        }
        if code != 0 {
            return Err("Read-only account lookup failed or exceeded its buffer bound".into());
        }
        if found.is_null() {
            return Ok(None);
        }
        // SAFETY: successful non-null NSS result initializes record; libc owns
        // the NUL-terminated field layout within the still-live caller buffer.
        let directory = unsafe {
            let record = record.assume_init();
            if record.pw_dir.is_null() {
                return Err("Account lookup returned no home directory".into());
            }
            CStr::from_ptr(record.pw_dir).to_bytes().to_vec()
        };
        return Ok(Some(PathBuf::from(OsString::from_vec(directory))));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    #[test]
    fn frozen_platform_pathlib_expansion_retains_names_and_errors() {
        let reference: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/selfhost-bundle-path-reference.json"
        ))
        .unwrap();
        let mut checked = 0;
        for case in reference["cases"].as_array().unwrap() {
            if case["platform"] != if cfg!(windows) { "windows" } else { "posix" } {
                continue;
            }
            let env = |key: &str| case["environment"][key].as_str().map(OsString::from);
            let observed = expand_with(case["input"].as_str().unwrap().into(), |name| {
                #[cfg(windows)]
                {
                    Ok(windows_home(name, env))
                }
                #[cfg(unix)]
                {
                    posix_home(name, env("HOME"), |name| {
                        Ok(
                            case["accounts"][name.map_or("uid", |name| name.to_str().unwrap())]
                                .as_str()
                                .map(PathBuf::from),
                        )
                    })
                }
            });
            match case["expanded"].as_str() {
                Some(expected) => {
                    assert_eq!(observed.unwrap(), Path::new(expected), "{}", case["name"])
                }
                None => assert_eq!(observed.unwrap_err(), case["message"].as_str().unwrap()),
            }
            checked += 1;
        }
        assert_eq!(checked, if cfg!(windows) { 17 } else { 9 });
    }

    #[cfg(unix)]
    #[test]
    fn real_read_only_account_lookup_handles_current_and_unknown_names() {
        assert!(account_home(None).unwrap().is_some());
        // Establish a known system account independently of the production NSS
        // wrapper. This public account database is not /etc/shadow; never emit
        // its contents or consult operator HOME/USER values for expectations.
        let accounts = std::fs::read_to_string("/etc/passwd").unwrap();
        let mut roots = accounts
            .lines()
            .map(|line| line.split(':').collect::<Vec<_>>())
            .filter(|fields| fields.first() == Some(&"root"));
        let root = roots.next().expect("known root system account");
        assert!(roots.next().is_none(), "unique root system account");
        assert_eq!(root.len(), 7);
        assert_eq!(root[2], "0");
        let expected = PathBuf::from(root[5]);
        assert!(expected.is_absolute());
        assert!(
            account_home(Some(OsStr::new(root[0]))).unwrap() == Some(expected.clone()),
            "named NSS home must match the independent system account"
        );
        assert!(
            expand(PathBuf::from("~root/packager-test")).unwrap() == expected.join("packager-test"),
            "named expansion must retain the independently established home"
        );
        assert!(account_home(Some(OsStr::new(
            "marty-packager-nonexistent-account-94b2fe13"
        )))
        .unwrap()
        .is_none());
        assert!(account_home(Some(OsStr::new("bad\0name"))).is_err());
    }
}
