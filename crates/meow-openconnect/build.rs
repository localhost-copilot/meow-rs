fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "dtls")]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("musl")
    {
        musl::build();
    }
}

#[cfg(feature = "dtls")]
mod musl {
    use std::collections::BTreeSet;
    use std::ffi::OsString;
    use std::path::Path;
    use std::process::Command;

    const PREFIX: &str = "meow_oc_";

    fn tool(variable: &str, default: &str) -> OsString {
        println!("cargo:rerun-if-env-changed={variable}");
        std::env::var_os(variable).unwrap_or_else(|| default.into())
    }

    fn output(command: &mut Command) -> String {
        let result = command.output().unwrap_or_else(|error| {
            panic!("cannot run {command:?}: {error}; musl DTLS requires LLVM nm and objcopy")
        });
        assert!(
            result.status.success(),
            "{command:?} failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).expect("tool output must be UTF-8")
    }

    fn symbols(nm: &OsString, path: &Path, defined: bool) -> BTreeSet<String> {
        output(
            Command::new(nm)
                .args([
                    "--extern-only",
                    "--format=posix",
                    if defined {
                        "--defined-only"
                    } else {
                        "--undefined-only"
                    },
                ])
                .arg(path),
        )
        .lines()
        .filter(|line| !line.ends_with(':')) // Archive member headers.
        .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
        .collect()
    }

    pub fn build() {
        let nm = tool("MEOW_OPENCONNECT_NM", "llvm-nm");
        let objcopy = tool("MEOW_OPENCONNECT_OBJCOPY", "llvm-objcopy");
        let artifacts = openssl_src::Build::new().build();
        let configuration =
            std::fs::read_to_string(artifacts.include_dir().join("openssl/configuration.h"))
                .unwrap();
        // Cargo feature unification must not let another consumer enable DSO
        // loading: external provider modules would not share our symbol prefix.
        assert!(
            configuration
                .lines()
                .any(|line| line
                    .split_whitespace()
                    .eq(["#", "define", "OPENSSL_NO_DSO"])),
            "musl DTLS requires OpenSSL built without DSO loading"
        );
        let source = artifacts.lib_dir();
        // boring-sys also links ssl/crypto by name. Never put OpenSSL's original
        // archives on the linker search path, even alongside our renamed ones.
        let directory = source.join("isolated");
        std::fs::create_dir_all(&directory).unwrap();
        let archives = [source.join("libssl.a"), source.join("libcrypto.a")];
        // Rename definitions AND references across both archives. Prefixing all
        // symbols indiscriminately would also rename unresolved libc functions.
        let names: BTreeSet<_> = archives
            .iter()
            .flat_map(|p| symbols(&nm, p, true))
            .collect();
        assert!(
            names.contains("SSL_new") && names.contains("RAND_bytes"),
            "missing OpenSSL symbols"
        );
        let mapping = directory.join("meow-openssl-symbols.txt");
        std::fs::write(
            &mapping,
            names
                .iter()
                .map(|name| format!("{name} {PREFIX}{name}\n"))
                .collect::<String>(),
        )
        .unwrap();
        for (source, library) in archives.iter().zip(["meow_oc_ssl", "meow_oc_crypto"]) {
            let destination = directory.join(format!("lib{library}.a"));
            output(
                Command::new(&objcopy)
                    .arg(format!("--redefine-syms={}", mapping.display()))
                    .arg(source)
                    .arg(&destination),
            );
            let expected: BTreeSet<_> = symbols(&nm, source, true)
                .iter()
                .map(|name| format!("{PREFIX}{name}"))
                .collect();
            assert_eq!(
                symbols(&nm, &destination, true),
                expected,
                "incomplete OpenSSL symbol isolation"
            );
            assert!(
                symbols(&nm, &destination, false).is_disjoint(&names),
                "unprefixed OpenSSL reference"
            );
            println!("cargo:rustc-link-lib=static={library}");
        }
        // Do not call print_cargo_metadata: it would link unprefixed ssl/crypto.
        println!("cargo:rustc-link-search=native={}", directory.display());
    }
}
