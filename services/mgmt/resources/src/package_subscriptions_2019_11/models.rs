#![doc = "generated by AutoRust"]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct CheckResourceNameResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<check_resource_name_result::Status>,
}
impl CheckResourceNameResult {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod check_resource_name_result {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Status {
        Allowed,
        Reserved,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ErrorDefinition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}
impl ErrorDefinition {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ErrorResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorDefinition>,
}
impl ErrorResponse {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Location {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "subscriptionId", default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "regionalDisplayName", default, skip_serializing_if = "Option::is_none")]
    pub regional_display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<LocationMetadata>,
}
impl Location {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct LocationListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<Location>,
}
impl LocationListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct LocationMetadata {
    #[serde(rename = "regionType", default, skip_serializing_if = "Option::is_none")]
    pub region_type: Option<location_metadata::RegionType>,
    #[serde(rename = "regionCategory", default, skip_serializing_if = "Option::is_none")]
    pub region_category: Option<location_metadata::RegionCategory>,
    #[serde(rename = "geographyGroup", default, skip_serializing_if = "Option::is_none")]
    pub geography_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub longitude: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latitude: Option<String>,
    #[serde(rename = "physicalLocation", default, skip_serializing_if = "Option::is_none")]
    pub physical_location: Option<String>,
    #[serde(rename = "pairedRegion", default, skip_serializing_if = "Vec::is_empty")]
    pub paired_region: Vec<PairedRegion>,
}
impl LocationMetadata {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod location_metadata {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum RegionType {
        Physical,
        Logical,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum RegionCategory {
        Recommended,
        Other,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ManagedByTenant {
    #[serde(rename = "tenantId", default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}
impl ManagedByTenant {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Operation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<operation::Display>,
}
impl Operation {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod operation {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
    pub struct Display {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }
    impl Display {
        pub fn new() -> Self {
            Self::default()
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct OperationListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<Operation>,
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl OperationListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct PairedRegion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "subscriptionId", default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
}
impl PairedRegion {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceName {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
}
impl ResourceName {
    pub fn new(name: String, type_: String) -> Self {
        Self { name, type_ }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Subscription {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "subscriptionId", default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "tenantId", default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<subscription::State>,
    #[serde(rename = "subscriptionPolicies", default, skip_serializing_if = "Option::is_none")]
    pub subscription_policies: Option<SubscriptionPolicies>,
    #[serde(rename = "authorizationSource", default, skip_serializing_if = "Option::is_none")]
    pub authorization_source: Option<String>,
    #[serde(rename = "managedByTenants", default, skip_serializing_if = "Vec::is_empty")]
    pub managed_by_tenants: Vec<ManagedByTenant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
impl Subscription {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod subscription {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum State {
        Enabled,
        Warned,
        PastDue,
        Disabled,
        Deleted,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubscriptionListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<Subscription>,
    #[serde(rename = "nextLink")]
    pub next_link: String,
}
impl SubscriptionListResult {
    pub fn new(next_link: String) -> Self {
        Self {
            value: Vec::new(),
            next_link,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SubscriptionPolicies {
    #[serde(rename = "locationPlacementId", default, skip_serializing_if = "Option::is_none")]
    pub location_placement_id: Option<String>,
    #[serde(rename = "quotaId", default, skip_serializing_if = "Option::is_none")]
    pub quota_id: Option<String>,
    #[serde(rename = "spendingLimit", default, skip_serializing_if = "Option::is_none")]
    pub spending_limit: Option<subscription_policies::SpendingLimit>,
}
impl SubscriptionPolicies {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod subscription_policies {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum SpendingLimit {
        On,
        Off,
        CurrentPeriodOff,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct TenantIdDescription {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "tenantId", default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(rename = "tenantCategory", default, skip_serializing_if = "Option::is_none")]
    pub tenant_category: Option<tenant_id_description::TenantCategory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(rename = "countryCode", default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
}
impl TenantIdDescription {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod tenant_id_description {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum TenantCategory {
        Home,
        ProjectedBy,
        ManagedBy,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TenantListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<TenantIdDescription>,
    #[serde(rename = "nextLink")]
    pub next_link: String,
}
impl TenantListResult {
    pub fn new(next_link: String) -> Self {
        Self {
            value: Vec::new(),
            next_link,
        }
    }
}
