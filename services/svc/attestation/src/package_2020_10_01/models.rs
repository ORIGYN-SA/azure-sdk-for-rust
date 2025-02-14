#![doc = "generated by AutoRust"]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct AttestOpenEnclaveRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<String>,
    #[serde(rename = "runtimeData", default, skip_serializing_if = "Option::is_none")]
    pub runtime_data: Option<RuntimeData>,
    #[serde(rename = "initTimeData", default, skip_serializing_if = "Option::is_none")]
    pub init_time_data: Option<InitTimeData>,
    #[serde(rename = "draftPolicyForAttestation", default, skip_serializing_if = "Option::is_none")]
    pub draft_policy_for_attestation: Option<String>,
}
impl AttestOpenEnclaveRequest {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct AttestSgxEnclaveRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote: Option<String>,
    #[serde(rename = "runtimeData", default, skip_serializing_if = "Option::is_none")]
    pub runtime_data: Option<RuntimeData>,
    #[serde(rename = "initTimeData", default, skip_serializing_if = "Option::is_none")]
    pub init_time_data: Option<InitTimeData>,
    #[serde(rename = "draftPolicyForAttestation", default, skip_serializing_if = "Option::is_none")]
    pub draft_policy_for_attestation: Option<String>,
}
impl AttestSgxEnclaveRequest {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct AttestationCertificateManagementBody {
    #[serde(rename = "policyCertificate", default, skip_serializing_if = "Option::is_none")]
    pub policy_certificate: Option<JsonWebKey>,
}
impl AttestationCertificateManagementBody {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct AttestationResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<JsonWebToken>,
}
impl AttestationResponse {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct AttestationResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(rename = "x-ms-ver", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_ver: Option<String>,
    #[serde(rename = "x-ms-runtime", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_runtime: Option<serde_json::Value>,
    #[serde(rename = "x-ms-inittime", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_inittime: Option<serde_json::Value>,
    #[serde(rename = "x-ms-policy", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_policy: Option<serde_json::Value>,
    #[serde(rename = "x-ms-attestation-type", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_attestation_type: Option<String>,
    #[serde(rename = "x-ms-policy-signer", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_policy_signer: Option<JsonWebKey>,
    #[serde(rename = "x-ms-policy-hash", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_policy_hash: Option<String>,
    #[serde(rename = "x-ms-sgx-is-debuggable", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_sgx_is_debuggable: Option<bool>,
    #[serde(rename = "x-ms-sgx-product-id", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_sgx_product_id: Option<f64>,
    #[serde(rename = "x-ms-sgx-mrenclave", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_sgx_mrenclave: Option<String>,
    #[serde(rename = "x-ms-sgx-mrsigner", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_sgx_mrsigner: Option<String>,
    #[serde(rename = "x-ms-sgx-svn", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_sgx_svn: Option<f64>,
    #[serde(rename = "x-ms-sgx-ehd", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_sgx_ehd: Option<String>,
    #[serde(rename = "x-ms-sgx-collateral", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_sgx_collateral: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ver: Option<String>,
    #[serde(rename = "is-debuggable", default, skip_serializing_if = "Option::is_none")]
    pub is_debuggable: Option<bool>,
    #[serde(rename = "maa-attestationcollateral", default, skip_serializing_if = "Option::is_none")]
    pub maa_attestationcollateral: Option<serde_json::Value>,
    #[serde(rename = "aas-ehd", default, skip_serializing_if = "Option::is_none")]
    pub aas_ehd: Option<String>,
    #[serde(rename = "maa-ehd", default, skip_serializing_if = "Option::is_none")]
    pub maa_ehd: Option<String>,
    #[serde(rename = "product-id", default, skip_serializing_if = "Option::is_none")]
    pub product_id: Option<f64>,
    #[serde(rename = "sgx-mrenclave", default, skip_serializing_if = "Option::is_none")]
    pub sgx_mrenclave: Option<String>,
    #[serde(rename = "sgx-mrsigner", default, skip_serializing_if = "Option::is_none")]
    pub sgx_mrsigner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub svn: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_signer: Option<JsonWebKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_data: Option<String>,
}
impl AttestationResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct CloudError {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<CloudErrorBody>,
}
impl CloudError {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct CloudErrorBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
impl CloudErrorBody {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum DataType {
    Binary,
    #[serde(rename = "JSON")]
    Json,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct InitTimeData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(rename = "dataType", default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<DataType>,
}
impl InitTimeData {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonWebKey {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub x5c: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}
impl JsonWebKey {
    pub fn new(kty: String) -> Self {
        Self {
            alg: None,
            crv: None,
            d: None,
            dp: None,
            dq: None,
            e: None,
            k: None,
            kid: None,
            kty,
            n: None,
            p: None,
            q: None,
            qi: None,
            use_: None,
            x: None,
            x5c: Vec::new(),
            y: None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct JsonWebKeySet {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<JsonWebKey>,
}
impl JsonWebKeySet {
    pub fn new() -> Self {
        Self::default()
    }
}
pub type JsonWebToken = String;
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PolicyCertificatesModificationResult {
    #[serde(rename = "x-ms-certificate-thumbprint", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_certificate_thumbprint: Option<String>,
    #[serde(rename = "x-ms-policycertificates-result", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_policycertificates_result: Option<policy_certificates_modification_result::XMsPolicycertificatesResult>,
}
impl PolicyCertificatesModificationResult {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod policy_certificates_modification_result {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum XMsPolicycertificatesResult {
        IsPresent,
        IsAbsent,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PolicyCertificatesModifyResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<JsonWebToken>,
}
impl PolicyCertificatesModifyResponse {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PolicyCertificatesResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<JsonWebToken>,
}
impl PolicyCertificatesResponse {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PolicyCertificatesResult {
    #[serde(rename = "x-ms-policy-certificates", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_policy_certificates: Option<JsonWebKeySet>,
}
impl PolicyCertificatesResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PolicyResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<JsonWebToken>,
}
impl PolicyResponse {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PolicyResult {
    #[serde(rename = "x-ms-policy-result", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_policy_result: Option<policy_result::XMsPolicyResult>,
    #[serde(rename = "x-ms-policy-token-hash", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_policy_token_hash: Option<String>,
    #[serde(rename = "x-ms-policy-signer", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_policy_signer: Option<JsonWebKey>,
    #[serde(rename = "x-ms-policy", default, skip_serializing_if = "Option::is_none")]
    pub x_ms_policy: Option<JsonWebToken>,
}
impl PolicyResult {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod policy_result {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum XMsPolicyResult {
        Updated,
        Removed,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct RuntimeData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(rename = "dataType", default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<DataType>,
}
impl RuntimeData {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct StoredAttestationPolicy {
    #[serde(rename = "AttestationPolicy", default, skip_serializing_if = "Option::is_none")]
    pub attestation_policy: Option<String>,
}
impl StoredAttestationPolicy {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct TpmAttestationRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}
impl TpmAttestationRequest {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct TpmAttestationResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}
impl TpmAttestationResponse {
    pub fn new() -> Self {
        Self::default()
    }
}
