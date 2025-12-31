// compiler/src/config/mod.rs

//! Configuration module for ESP Compiler
//! Uses common crate for shared config, adds compiler-specific build info

// Re-export runtime types from common (no conflict)
pub use common::config::runtime;

// Include generated constants from build.rs (this defines compile_time)
include!(concat!(env!("OUT_DIR"), "/constants.rs"));

/// Build information and configuration metadata (compiler-specific)
pub mod build_info {
    pub fn profile() -> &'static str {
        option_env!("ESP_BUILD_PROFILE").unwrap_or("development")
    }

    pub fn config_dir() -> &'static str {
        option_env!("ESP_CONFIG_DIR").unwrap_or("config")
    }

    pub fn source_info() -> String {
        format!("Generated from {}/{}.toml", config_dir(), profile())
    }

    pub fn constants_generated() -> bool {
        true
    }

    pub fn out_dir() -> &'static str {
        env!("OUT_DIR")
    }
}
