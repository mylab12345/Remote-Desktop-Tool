//! Platform abstraction for RDT.
//!
//! Everything that differs between Windows, Ubuntu/Debian and the RHEL family
//! lives here: filesystem locations, OS detection, dependency probing, service
//! installation (systemd units / Windows SCM) and the few privileged helpers
//! the rest of the workspace needs.
// This crate is the only place in the workspace that calls libc and the Win32
// API directly (OS identity, file ownership, privilege checks, service
// control).  Those calls are inherently unsafe, each one carries a `SAFETY`
// comment, and they are confined here; every other crate denies `unsafe_code`.
#![allow(unsafe_code)]
#![cfg_attr(not(any(unix, windows)), allow(unused))]

pub mod deps;
pub mod info;
pub mod paths;
pub mod service;

pub mod platform_impl;

pub use crate::deps::{
    probe_dependencies, which, DependencyId, DependencyReport, DependencyStatus, DependencySuite,
};
pub use crate::info::{DistroInfo, OsFamily, PlatformInfo};
pub use crate::paths::AppPaths;
pub use crate::platform_impl::{hostname, restrict_dir_to_owner, restrict_to_owner};
pub use crate::service::{
    install_service, service_status, uninstall_service, ServiceInstallRequest, ServiceSpec,
    ServiceState,
};
