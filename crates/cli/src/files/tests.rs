use super::*;

#[test]
fn replacing_keeps_permissions_and_leaves_no_partial_file() {
    let directory = std::env::temp_dir().join(format!("neutrin0-replace-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("config.toml");
    fs::write(&path, "old").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    replace_file(&path, b"new").unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "new");
    assert!(!path.with_extension("partial").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    fs::remove_dir_all(&directory).unwrap();
}
