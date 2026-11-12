//! Embeds the built web UI (`src/ui/dist`, Vite's output) at compile time, so
//! the install needs no separate UI directory (rust/PLAN.md, frozen contract
//! item 5). Only `index.html` and regular files directly in `assets/` are
//! listed; `ui::server::embedded_dist` applies the same name and type
//! allowlist as `loadDist` when it reads them. A tree without the built UI
//! (a copy of `rust/` alone, as `cargo xtask mutation` makes) embeds nothing.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let dist = std::env::var_os("AV_UI_DIST")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../../src/ui/dist"));
    println!("cargo:rerun-if-env-changed=AV_UI_DIST");
    println!("cargo:rerun-if-changed={}", dist.display());
    let mut out = String::from("/// The built UI embedded at compile time: (path under dist, bytes).\n");
    out.push_str("pub static EMBEDDED: &[(&str, &[u8])] = &[\n");
    for (name, path) in files(&dist) {
        println!("cargo:rerun-if-changed={}", path.display());
        let _ = writeln!(
            out,
            "    ({:?}, include_bytes!({:?})),",
            name,
            path.display().to_string()
        );
    }
    out.push_str("];\n");
    let dest = PathBuf::from(std::env::var_os("OUT_DIR").expect("out dir")).join("dist.rs");
    std::fs::write(dest, out).expect("write dist.rs");
}

fn files(dist: &Path) -> Vec<(String, PathBuf)> {
    let mut found = Vec::new();
    let regular = |p: &Path| std::fs::symlink_metadata(p).map(|m| m.file_type().is_file()).unwrap_or(false);
    let index = dist.join("index.html");
    if !regular(&index) {
        return found;
    }
    found.push(("index.html".to_string(), index));
    if let Ok(entries) = std::fs::read_dir(dist.join("assets")) {
        let mut names: Vec<_> = entries.flatten().collect();
        names.sort_by_key(|e| e.file_name());
        for e in names {
            let path = e.path();
            if let Some(name) = e.file_name().to_str() {
                if regular(&path) {
                    found.push((format!("assets/{name}"), path));
                }
            }
        }
    }
    found
}
