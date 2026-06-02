use serde::{Deserialize, Serialize};

pub mod apt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMode {
    Security,
    Full,
    DryRun,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageInfo {
    pub name: String,
    pub installed_version: String,
    pub candidate_version: String,
    pub security: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanResult {
    pub packages: Vec<PackageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplyResult {
    pub mode: String,
    pub reboot_required: bool,
    pub packages: Vec<PackageInfo>,
}