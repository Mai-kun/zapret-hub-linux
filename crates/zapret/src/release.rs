//! The latest GitHub release of Flowseal or bol-van/zapret2, downloaded with `curl` and unpacked
//! into a new folder. Only these two repositories and their asset names: nothing the page or the
//! pipe sends becomes a URL.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context as _;

/// Part of every error where the destination was missing or unwritable; the page explains it.
pub const BLOCKED: &str = "missing or unwritable: check permissions and free space";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, specta::Type)]
pub enum Engine {
    Flowseal,
    Zapret2,
}

impl Engine {
    fn repo(self) -> &'static str {
        match self {
            Self::Flowseal => "Flowseal/zapret-discord-youtube",
            Self::Zapret2 => "bol-van/zapret2",
        }
    }

    /// The zip is `<prefix><tag>.zip`, the folder `<prefix><tag>`.
    fn prefix(self) -> &'static str {
        match self {
            Self::Flowseal => "zapret-discord-youtube-",
            Self::Zapret2 => "zapret2-",
        }
    }

    pub fn api_url(self) -> String {
        format!(
            "https://api.github.com/repos/{}/releases/latest",
            self.repo()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    pub url: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub tag: String,
    pub zip: Asset,
    /// `sha256sum.txt`: zapret2 always has one, Flowseal none.
    pub sums: Option<Asset>,
}

/// What a finished download left.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, specta::Type)]
pub struct Downloaded {
    pub dir: String,
    pub tag: String,
    /// SHA-256 of the zip as downloaded.
    pub sha256: String,
}

/// The release in the answer of `releases/latest`: the tag, the zip named after it and, for
/// zapret2, `sha256sum.txt`; each URL must be a download of the same repository.
pub fn select(engine: Engine, json: &str) -> anyhow::Result<Release> {
    let value: serde_json::Value =
        serde_json::from_str(json).context("GitHub answered with something other than JSON")?;
    let tag = value["tag_name"]
        .as_str()
        .context("the GitHub answer has no tag_name")?;
    anyhow::ensure!(
        !tag.is_empty()
            && tag.len() <= 64
            && tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "unexpected release tag {tag:?}"
    );
    let assets = value["assets"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let find = |name: &str| -> anyhow::Result<Option<Asset>> {
        let Some(asset) = assets.iter().find(|a| a["name"].as_str() == Some(name)) else {
            return Ok(None);
        };
        let url = asset["browser_download_url"].as_str().unwrap_or_default();
        let expected = format!("https://github.com/{}/releases/download/", engine.repo());
        anyhow::ensure!(
            url.starts_with(&expected),
            "{name} points outside {}: {url}",
            engine.repo()
        );
        Ok(Some(Asset {
            name: name.to_owned(),
            url: url.to_owned(),
            size: asset["size"].as_u64().unwrap_or(0),
        }))
    };
    let zip_name = format!("{}{tag}.zip", engine.prefix());
    let zip = find(&zip_name)?
        .with_context(|| format!("release {tag} of {} has no {zip_name}", engine.repo()))?;
    let sums = find("sha256sum.txt")?;
    anyhow::ensure!(
        engine == Engine::Flowseal || sums.is_some(),
        "release {tag} of {} has no sha256sum.txt",
        engine.repo()
    );
    Ok(Release {
        tag: tag.to_owned(),
        zip,
        sums: if engine == Engine::Zapret2 {
            sums
        } else {
            None
        },
    })
}

/// Where a release goes unless the user picks another folder: `$XDG_DATA_HOME`, else
/// `~/.local/share`. The folder is created here: `target` refuses a parent that does not exist.
pub fn default_parent() -> PathBuf {
    let dir = data_home(
        std::env::var_os("XDG_DATA_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    );
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// `$XDG_DATA_HOME` when set and non-empty, else `$HOME/.local/share`.
fn data_home(xdg: Option<&OsStr>, home: Option<&OsStr>) -> PathBuf {
    xdg.filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            home.filter(|v| !v.is_empty())
                .map(|home| PathBuf::from(home).join(".local/share"))
        })
        .unwrap_or_default()
}

/// `<parent>\<prefix><tag>`: refused when it exists and is not an empty folder.
pub fn target(parent: &Path, engine: Engine, tag: &str) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(
        parent.is_absolute() && parent.is_dir(),
        "{} is not an existing folder",
        parent.display()
    );
    let dir = parent.join(format!("{}{tag}", engine.prefix()));
    if dir.exists() {
        let empty = std::fs::read_dir(&dir).is_ok_and(|mut entries| entries.next().is_none());
        anyhow::ensure!(
            empty,
            "{} already exists and is not empty: choose another folder or remove it",
            dir.display()
        );
    }
    Ok(dir)
}

/// `<hash>  <path>` lines of `sha256sum.txt`; `*path` (binary mode) and `./` are stripped.
pub fn parse_sums(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let (hash, path) = line.trim().split_once(char::is_whitespace)?;
            let path = path.trim().trim_start_matches('*').replace('\\', "/");
            let path = path.trim_start_matches("./");
            (hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
                .then(|| (hash.to_ascii_lowercase(), path.to_owned()))
        })
        .collect()
}

/// The part of a listed path under the release root, for the files that run: the binaries
/// and the Lua. The release's own top folder, when listed, is skipped.
fn checked_path(path: &str) -> Option<String> {
    let path = path.replace('\\', "/");
    let wanted = |p: &str| p.starts_with("binaries/") || p.starts_with("lua/");
    if wanted(&path) {
        return Some(path);
    }
    path.split_once('/')
        .map(|(_, rest)| rest.to_owned())
        .filter(|p| wanted(p))
}

/// Checks every engine binary and Lua file `sums` lists under `root`; how many were checked.
pub fn verify(root: &Path, sums: &str) -> anyhow::Result<usize> {
    let mut checked = 0;
    for (hash, path) in parse_sums(sums) {
        let Some(rel) = checked_path(&path) else {
            continue;
        };
        let file = root.join(rel);
        let actual = hash_file(&file)?;
        anyhow::ensure!(
            actual == hash,
            "{} does not match sha256sum.txt: {actual} instead of {hash}",
            file.display()
        );
        checked += 1;
    }
    anyhow::ensure!(
        checked > 0,
        "sha256sum.txt lists no engine binaries or Lua files"
    );
    Ok(checked)
}

fn hash_file(file: &Path) -> anyhow::Result<String> {
    std::fs::read(file)
        .map(|bytes| crate::sha256_hex(&bytes))
        .map_err(|err| io_error(file, &err))
}

/// A file that should be there but is not, or a path that was never writable.
fn io_error(file: &Path, err: &std::io::Error) -> anyhow::Error {
    if err.kind() == std::io::ErrorKind::NotFound {
        anyhow::anyhow!("{}: {BLOCKED} ({err})", file.display())
    } else {
        anyhow::anyhow!("{}: {err}", file.display())
    }
}

/// Downloads and unpacks the latest release into a new folder under `parent`. `progress` gets the
/// bytes so far and the zip's size. On failure or cancel nothing is left but, after a blocked
/// write, the empty folder: the user fixes the permissions and tries again.
pub fn install(
    engine: Engine,
    parent: &Path,
    socks5: Option<&str>,
    cancel: &AtomicBool,
    progress: &dyn Fn(u64, u64),
) -> anyhow::Result<Downloaded> {
    let release = select(engine, &probe::curl::fetch_text(&engine.api_url(), socks5)?)?;
    let sums = match &release.sums {
        Some(asset) => Some(probe::curl::fetch_text(&asset.url, socks5)?),
        None => None,
    };
    let dir = target(parent, engine, &release.tag)?;
    std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let sha256 = match unpack(&release, sums.as_deref(), &dir, socks5, cancel, progress) {
        Ok(sha256) => {
            let _ = std::fs::remove_dir_all(dir.join(STAGING));
            sha256
        }
        Err(err) => {
            let _ = std::fs::remove_dir_all(&dir);
            if !format!("{err:#}").contains(BLOCKED) {
                return Err(err);
            }
            let _ = std::fs::create_dir_all(&dir);
            return Err(err.context(format!(
                "cannot write to {}: check permissions and free space, then download again",
                dir.display()
            )));
        }
    };
    log::info!(
        "{} {} unpacked into {}, zip SHA-256 {sha256}",
        engine.repo(),
        release.tag,
        dir.display()
    );
    Ok(Downloaded {
        dir: dir.display().to_string(),
        tag: release.tag,
        sha256,
    })
}

/// Inside the new folder: the zip and the raw unpack, together and removed when done.
const STAGING: &str = ".zapret-hub-download";

/// The zip's SHA-256 once the release is in `dir`.
fn unpack(
    release: &Release,
    sums: Option<&str>,
    dir: &Path,
    socks5: Option<&str>,
    cancel: &AtomicBool,
    progress: &dyn Fn(u64, u64),
) -> anyhow::Result<String> {
    let staging = dir.join(STAGING);
    std::fs::create_dir_all(&staging)?;
    let zip = staging.join(&release.zip.name);
    probe::curl::with_fallback(socks5, |proxy| {
        anyhow::ensure!(!cancel.load(Ordering::Relaxed), "canceled");
        download(&release.zip, &zip, proxy, cancel, progress)
    })?;
    anyhow::ensure!(!cancel.load(Ordering::Relaxed), "canceled");
    let sha256 = hash_file(&zip)?;
    log::info!("{} SHA-256 {sha256}", release.zip.name);
    if let Some(listed) = sums.and_then(|sums| {
        parse_sums(sums)
            .into_iter()
            .find(|(_, path)| path.rsplit('/').next() == Some(release.zip.name.as_str()))
    }) {
        anyhow::ensure!(
            listed.0 == sha256,
            "{} does not match sha256sum.txt: {sha256} instead of {}",
            release.zip.name,
            listed.0
        );
    }
    let raw = staging.join("x");
    expand(&zip, &raw, cancel)?;
    let root = content_root(&raw)?;
    match sums {
        Some(sums) => {
            verify(&root, sums)?;
        }
        None => {
            let missing = crate::folder::missing_parts(&root);
            anyhow::ensure!(
                missing.is_empty(),
                "the release unpacked without {}: {BLOCKED}",
                missing.join(", ")
            );
        }
    }
    move_up(&root, dir)?;
    chmod_nfqws(dir);
    Ok(sha256)
}

/// The unpack loses the Linux executables' rights: `nfqws2` gets them back, plus the caps its
/// queue needs, best effort — without them only a root run works, and the launch errors say that.
fn chmod_nfqws(dir: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let Some(binaries) = std::fs::read_dir(dir.join("binaries")).ok() else {
        return;
    };
    for entry in binaries.flatten() {
        let nfqws = entry.path().join("nfqws2");
        if !nfqws.is_file() {
            continue;
        }
        if let Err(err) = std::fs::set_permissions(&nfqws, std::fs::Permissions::from_mode(0o755)) {
            log::warn!("{} did not become executable: {err}", nfqws.display());
        }
        if let Err(err) = crate::root::run(
            "setcap",
            &["cap_net_admin,cap_net_raw=+ep", nfqws.display().to_string().as_str()],
        ) {
            log::warn!(
                "{} did not get its network capabilities: {err:#}",
                nfqws.display()
            );
        }
    }
}

fn download(
    asset: &Asset,
    dest: &Path,
    proxy: Option<&str>,
    cancel: &AtomicBool,
    progress: &dyn Fn(u64, u64),
) -> anyhow::Result<()> {
    let mut cmd = probe::curl::get(&asset.url, proxy);
    cmd.args(["-m", "900", "-o"]).arg(dest);
    let out = std::thread::scope(|scope| {
        let run = scope.spawn(|| exec::run(&mut cmd, Duration::from_secs(910), Some(cancel)));
        while !run.is_finished() {
            progress(std::fs::metadata(dest).map_or(0, |m| m.len()), asset.size);
            std::thread::sleep(Duration::from_millis(250));
        }
        run.join()
            .unwrap_or_else(|_| Err(std::io::Error::other("curl panicked")))
    })?;
    if out.canceled {
        anyhow::bail!("canceled");
    }
    // 23: curl could not write the file: no space, or no permission to write there.
    if out.code == Some(23) {
        anyhow::bail!("{}: {BLOCKED}\n\n{}", dest.display(), out.describe());
    }
    out.check()?;
    let size = std::fs::metadata(dest)
        .map_err(|err| io_error(dest, &err))?
        .len();
    progress(size, asset.size);
    Ok(())
}

/// The unpack with `bsdtar` (libarchive is on every system here).
fn expand(zip: &Path, dest: &Path, cancel: &AtomicBool) -> anyhow::Result<()> {
    std::fs::create_dir_all(dest)
        .with_context(|| format!("cannot create {}", dest.display()))?;
    let mut cmd = Command::new("bsdtar");
    cmd.arg("-xf").arg(zip).arg("-C").arg(dest);
    let out = exec::run(&mut cmd, Duration::from_secs(300), Some(cancel))?;
    if out.canceled {
        anyhow::bail!("canceled");
    }
    out.check()?;
    Ok(())
}

/// The unpacked release: its one top folder when the zip has one, else everything.
fn content_root(raw: &Path) -> anyhow::Result<PathBuf> {
    let entries: Vec<_> = std::fs::read_dir(raw)?.collect::<Result<_, _>>()?;
    Ok(match entries.as_slice() {
        [only] if only.file_type()?.is_dir() => only.path(),
        _ => raw.to_path_buf(),
    })
}

fn move_up(root: &Path, dir: &Path) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let to = dir.join(entry.file_name());
        std::fs::rename(entry.path(), &to).with_context(|| {
            format!("cannot move {} to {}", entry.path().display(), to.display())
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api(tag: &str, assets: &[(&str, &str)]) -> String {
        let assets: Vec<_> = assets
            .iter()
            .map(|(name, url)| serde_json::json!({"name": name, "browser_download_url": url, "size": 42}))
            .collect();
        serde_json::json!({"tag_name": tag, "assets": assets}).to_string()
    }

    const FS: &str = "https://github.com/Flowseal/zapret-discord-youtube/releases/download/1.9.3/";
    const Z2: &str = "https://github.com/bol-van/zapret2/releases/download/v0.9.4/";

    #[test]
    fn picks_the_zip_named_after_the_tag() {
        let json = api(
            "1.9.3",
            &[
                ("zapret-discord-youtube-1.9.3.rar", FS),
                (
                    "zapret-discord-youtube-1.9.3.zip",
                    &format!("{FS}zapret-discord-youtube-1.9.3.zip"),
                ),
            ],
        );
        let release = select(Engine::Flowseal, &json).unwrap();
        assert_eq!(release.tag, "1.9.3");
        assert_eq!(release.zip.name, "zapret-discord-youtube-1.9.3.zip");
        assert_eq!(release.zip.size, 42);
        assert_eq!(release.sums, None);

        let json = api(
            "v0.9.4",
            &[
                ("zapret2-v0.9.4.zip", &format!("{Z2}zapret2-v0.9.4.zip")),
                ("zapret2-v0.9.4.tar.gz", Z2),
                ("sha256sum.txt", &format!("{Z2}sha256sum.txt")),
            ],
        );
        let release = select(Engine::Zapret2, &json).unwrap();
        assert_eq!(release.zip.name, "zapret2-v0.9.4.zip");
        assert_eq!(release.sums.unwrap().name, "sha256sum.txt");
    }

    #[test]
    fn refuses_missing_assets_foreign_urls_and_odd_tags() {
        let no_sums = api("v0.9.4", &[("zapret2-v0.9.4.zip", Z2)]);
        assert!(select(Engine::Zapret2, &no_sums).is_err());
        let foreign = api(
            "1.9.3",
            &[(
                "zapret-discord-youtube-1.9.3.zip",
                "https://evil.example/x.zip",
            )],
        );
        assert!(select(Engine::Flowseal, &foreign).is_err());
        let other_repo = api("1.9.3", &[("zapret-discord-youtube-1.9.3.zip", Z2)]);
        assert!(select(Engine::Flowseal, &other_repo).is_err());
        let traversal = api("..\\..\\x", &[]);
        assert!(select(Engine::Flowseal, &traversal).is_err());
        assert!(select(Engine::Flowseal, &api("1.9.3", &[])).is_err());
        assert!(select(Engine::Flowseal, "<html>").is_err());
    }

    #[test]
    fn a_new_folder_or_an_empty_one_and_nothing_else() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = target(tmp.path(), Engine::Zapret2, "v0.9.4").unwrap();
        assert_eq!(dir, tmp.path().join("zapret2-v0.9.4"));
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(target(tmp.path(), Engine::Zapret2, "v0.9.4").unwrap(), dir);
        std::fs::write(dir.join("x"), "").unwrap();
        assert!(target(tmp.path(), Engine::Zapret2, "v0.9.4").is_err());
        let file = tmp.path().join("zapret-discord-youtube-1.9.3");
        std::fs::write(&file, "").unwrap();
        assert!(target(tmp.path(), Engine::Flowseal, "1.9.3").is_err());
        assert!(target(&tmp.path().join("nope"), Engine::Flowseal, "1.9.3").is_err());
        assert!(target(Path::new("relative"), Engine::Flowseal, "1.9.3").is_err());
    }

    #[test]
    fn checks_the_binaries_and_lua_against_sha256sum() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let exe = root.join("binaries").join("windows-x86_64").join("winws2.exe");
        let nfqws = root.join("binaries").join("linux-x86_64").join("nfqws2");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::create_dir_all(nfqws.parent().unwrap()).unwrap();
        std::fs::create_dir_all(root.join("lua")).unwrap();
        std::fs::write(&exe, "exe").unwrap();
        std::fs::write(&nfqws, "elsewhere").unwrap();
        std::fs::write(root.join("lua").join("zapret-lib.lua"), "lua").unwrap();
        let sums = format!(
            "{}  ./zapret2-v0.9.4/binaries/windows-x86_64/winws2.exe\n\
             {} *lua/zapret-lib.lua\n\
             {}  binaries/linux-x86_64/nfqws2\n",
            crate::sha256_hex(b"exe"),
            crate::sha256_hex(b"lua"),
            crate::sha256_hex(b"elsewhere"),
        );
        assert_eq!(
            verify(root, &sums).unwrap(),
            3,
            "the linux binary is checked too"
        );

        std::fs::write(&exe, "tampered").unwrap();
        let err = verify(root, &sums).unwrap_err().to_string();
        assert!(err.contains("does not match"), "{err}");

        std::fs::remove_file(&exe).unwrap();
        let err = verify(root, &sums).unwrap_err().to_string();
        assert!(
            err.contains(BLOCKED),
            "a vanished file is a missing or unwritable destination: {err}"
        );

        let none = format!(
            "{}  binaries/linux-x86_64/nfqws2\n",
            crate::sha256_hex(b"x")
        );
        assert!(verify(root, &none).is_err(), "nothing checked is a failure");
    }

    #[test]
    fn data_home_prefers_xdg_then_home() {
        let home = OsStr::new("/home/me");
        assert_eq!(
            data_home(Some(OsStr::new("/data")), Some(home)),
            PathBuf::from("/data")
        );
        assert_eq!(
            data_home(Some(OsStr::new("")), Some(home)),
            PathBuf::from("/home/me/.local/share")
        );
        assert_eq!(
            data_home(None, Some(home)),
            PathBuf::from("/home/me/.local/share")
        );
        assert_eq!(data_home(None, None), PathBuf::new());
    }

    #[test]
    fn a_single_top_folder_is_the_release_root() {
        let tmp = tempfile::tempdir().unwrap();
        let raw = tmp.path().join("x");
        std::fs::create_dir_all(raw.join("zapret2-v0.9.4").join("lua")).unwrap();
        assert_eq!(content_root(&raw).unwrap(), raw.join("zapret2-v0.9.4"));
        std::fs::write(raw.join("sha256sum.txt"), "").unwrap();
        assert_eq!(content_root(&raw).unwrap(), raw);

        let dir = tmp.path().join("out");
        std::fs::create_dir(&dir).unwrap();
        move_up(&raw, &dir).unwrap();
        assert!(dir.join("sha256sum.txt").is_file() && dir.join("zapret2-v0.9.4").is_dir());
    }
}
