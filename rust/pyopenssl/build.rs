use std::env;

#[allow(clippy::unusual_byte_groupings)]
fn main() {
    println!("cargo:rustc-check-cfg=cfg(ossl300)");
    println!("cargo:rustc-check-cfg=cfg(ossl320)");
    println!("cargo:rustc-check-cfg=cfg(libressl)");
    println!("cargo:rustc-check-cfg=cfg(boringssl)");
    println!("cargo:rustc-check-cfg=cfg(awslc)");

    if env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_ok() {
        println!("cargo:rustc-cfg=libressl");
    }
    if env::var("CARGO_CFG_OSSL_BORINGSSL").is_ok() {
        println!("cargo:rustc-cfg=boringssl");
    }
    if env::var("CARGO_CFG_OSSL_AWSLC").is_ok() {
        println!("cargo:rustc-cfg=awslc");
    }
    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();
        if version >= 0x3_00_00_00_0 {
            println!("cargo:rustc-cfg=ossl300");
        }
        if version >= 0x3_02_00_00_0 {
            println!("cargo:rustc-cfg=ossl320");
        }
    }
}
