#![doc = "generated by AutoRust"]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckNameAvailability {
    pub name: String,
}
impl CheckNameAvailability {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct CheckNameAvailabilityResult {
    #[serde(rename = "nameAvailable", default, skip_serializing_if = "Option::is_none")]
    pub name_available: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<UnavailableReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
impl CheckNameAvailabilityResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum EntityAvailabilityStatus {
    Available,
    Limited,
    Renaming,
    Restoring,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum EntityStatus {
    Active,
    Creating,
    Deleting,
    Disabled,
    ReceiveDisabled,
    Renaming,
    Restoring,
    SendDisabled,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct MessageCountDetails {
    #[serde(rename = "activeMessageCount", default, skip_serializing_if = "Option::is_none")]
    pub active_message_count: Option<i64>,
    #[serde(rename = "deadLetterMessageCount", default, skip_serializing_if = "Option::is_none")]
    pub dead_letter_message_count: Option<i64>,
    #[serde(rename = "scheduledMessageCount", default, skip_serializing_if = "Option::is_none")]
    pub scheduled_message_count: Option<i64>,
    #[serde(rename = "transferDeadLetterMessageCount", default, skip_serializing_if = "Option::is_none")]
    pub transfer_dead_letter_message_count: Option<i64>,
    #[serde(rename = "transferMessageCount", default, skip_serializing_if = "Option::is_none")]
    pub transfer_message_count: Option<i64>,
}
impl MessageCountDetails {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NamespaceCreateOrUpdateParameters {
    pub location: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sku: Option<Sku>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<NamespaceProperties>,
}
impl NamespaceCreateOrUpdateParameters {
    pub fn new(location: String) -> Self {
        Self {
            location,
            sku: None,
            tags: None,
            properties: None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct NamespaceListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<NamespaceResource>,
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl NamespaceListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct NamespaceProperties {
    #[serde(rename = "provisioningState", default, skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<namespace_properties::Status>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(rename = "serviceBusEndpoint", default, skip_serializing_if = "Option::is_none")]
    pub service_bus_endpoint: Option<String>,
    #[serde(rename = "createACSNamespace", default, skip_serializing_if = "Option::is_none")]
    pub create_acs_namespace: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}
impl NamespaceProperties {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod namespace_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Status {
        Unknown,
        Creating,
        Created,
        Activating,
        Enabling,
        Active,
        Disabling,
        Disabled,
        SoftDeleting,
        SoftDeleted,
        Removing,
        Removed,
        Failed,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NamespaceResource {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sku: Option<Sku>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<NamespaceProperties>,
}
impl NamespaceResource {
    pub fn new(tracked_resource: TrackedResource) -> Self {
        Self {
            tracked_resource,
            sku: None,
            properties: None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct NamespaceUpdateParameters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sku: Option<Sku>,
}
impl NamespaceUpdateParameters {
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueueCreateOrUpdateParameters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub location: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<QueueProperties>,
}
impl QueueCreateOrUpdateParameters {
    pub fn new(location: String) -> Self {
        Self {
            name: None,
            location,
            properties: None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct QueueListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<QueueResource>,
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl QueueListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct QueueProperties {
    #[serde(rename = "lockDuration", default, skip_serializing_if = "Option::is_none")]
    pub lock_duration: Option<String>,
    #[serde(rename = "accessedAt", default, skip_serializing_if = "Option::is_none")]
    pub accessed_at: Option<String>,
    #[serde(rename = "autoDeleteOnIdle", default, skip_serializing_if = "Option::is_none")]
    pub auto_delete_on_idle: Option<String>,
    #[serde(rename = "entityAvailabilityStatus", default, skip_serializing_if = "Option::is_none")]
    pub entity_availability_status: Option<EntityAvailabilityStatus>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "defaultMessageTimeToLive", default, skip_serializing_if = "Option::is_none")]
    pub default_message_time_to_live: Option<String>,
    #[serde(rename = "duplicateDetectionHistoryTimeWindow", default, skip_serializing_if = "Option::is_none")]
    pub duplicate_detection_history_time_window: Option<String>,
    #[serde(rename = "enableBatchedOperations", default, skip_serializing_if = "Option::is_none")]
    pub enable_batched_operations: Option<bool>,
    #[serde(rename = "deadLetteringOnMessageExpiration", default, skip_serializing_if = "Option::is_none")]
    pub dead_lettering_on_message_expiration: Option<bool>,
    #[serde(rename = "enableExpress", default, skip_serializing_if = "Option::is_none")]
    pub enable_express: Option<bool>,
    #[serde(rename = "enablePartitioning", default, skip_serializing_if = "Option::is_none")]
    pub enable_partitioning: Option<bool>,
    #[serde(rename = "isAnonymousAccessible", default, skip_serializing_if = "Option::is_none")]
    pub is_anonymous_accessible: Option<bool>,
    #[serde(rename = "maxDeliveryCount", default, skip_serializing_if = "Option::is_none")]
    pub max_delivery_count: Option<i32>,
    #[serde(rename = "maxSizeInMegabytes", default, skip_serializing_if = "Option::is_none")]
    pub max_size_in_megabytes: Option<i64>,
    #[serde(rename = "messageCount", default, skip_serializing_if = "Option::is_none")]
    pub message_count: Option<i64>,
    #[serde(rename = "countDetails", default, skip_serializing_if = "Option::is_none")]
    pub count_details: Option<MessageCountDetails>,
    #[serde(rename = "requiresDuplicateDetection", default, skip_serializing_if = "Option::is_none")]
    pub requires_duplicate_detection: Option<bool>,
    #[serde(rename = "requiresSession", default, skip_serializing_if = "Option::is_none")]
    pub requires_session: Option<bool>,
    #[serde(rename = "sizeInBytes", default, skip_serializing_if = "Option::is_none")]
    pub size_in_bytes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<EntityStatus>,
    #[serde(rename = "supportOrdering", default, skip_serializing_if = "Option::is_none")]
    pub support_ordering: Option<bool>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}
impl QueueProperties {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct QueueResource {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<QueueProperties>,
}
impl QueueResource {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct RegenerateKeysParameters {
    #[serde(rename = "Policykey", default, skip_serializing_if = "Option::is_none")]
    pub policykey: Option<regenerate_keys_parameters::Policykey>,
}
impl RegenerateKeysParameters {
    pub fn new() -> Self {
        Self::default()
    }
}
pub mod regenerate_keys_parameters {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Policykey {
        PrimaryKey,
        SecondaryKey,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Resource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}
impl Resource {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ResourceListKeys {
    #[serde(rename = "primaryConnectionString", default, skip_serializing_if = "Option::is_none")]
    pub primary_connection_string: Option<String>,
    #[serde(rename = "secondaryConnectionString", default, skip_serializing_if = "Option::is_none")]
    pub secondary_connection_string: Option<String>,
    #[serde(rename = "primaryKey", default, skip_serializing_if = "Option::is_none")]
    pub primary_key: Option<String>,
    #[serde(rename = "secondaryKey", default, skip_serializing_if = "Option::is_none")]
    pub secondary_key: Option<String>,
    #[serde(rename = "keyName", default, skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
}
impl ResourceListKeys {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SharedAccessAuthorizationRuleCreateOrUpdateParameters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<SharedAccessAuthorizationRuleProperties>,
}
impl SharedAccessAuthorizationRuleCreateOrUpdateParameters {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SharedAccessAuthorizationRuleListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<SharedAccessAuthorizationRuleResource>,
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl SharedAccessAuthorizationRuleListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SharedAccessAuthorizationRuleProperties {
    pub rights: Vec<String>,
}
impl SharedAccessAuthorizationRuleProperties {
    pub fn new(rights: Vec<String>) -> Self {
        Self { rights }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SharedAccessAuthorizationRuleResource {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<SharedAccessAuthorizationRuleProperties>,
}
impl SharedAccessAuthorizationRuleResource {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Sku {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<sku::Name>,
    pub tier: sku::Tier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<i32>,
}
impl Sku {
    pub fn new(tier: sku::Tier) -> Self {
        Self {
            name: None,
            tier,
            capacity: None,
        }
    }
}
pub mod sku {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Name {
        Basic,
        Standard,
        Premium,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Tier {
        Basic,
        Standard,
        Premium,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubscriptionCreateOrUpdateParameters {
    pub location: String,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<SubscriptionProperties>,
}
impl SubscriptionCreateOrUpdateParameters {
    pub fn new(location: String) -> Self {
        Self {
            location,
            type_: None,
            properties: None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SubscriptionListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<SubscriptionResource>,
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl SubscriptionListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SubscriptionProperties {
    #[serde(rename = "accessedAt", default, skip_serializing_if = "Option::is_none")]
    pub accessed_at: Option<String>,
    #[serde(rename = "autoDeleteOnIdle", default, skip_serializing_if = "Option::is_none")]
    pub auto_delete_on_idle: Option<String>,
    #[serde(rename = "countDetails", default, skip_serializing_if = "Option::is_none")]
    pub count_details: Option<MessageCountDetails>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "defaultMessageTimeToLive", default, skip_serializing_if = "Option::is_none")]
    pub default_message_time_to_live: Option<String>,
    #[serde(
        rename = "deadLetteringOnFilterEvaluationExceptions",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub dead_lettering_on_filter_evaluation_exceptions: Option<bool>,
    #[serde(rename = "deadLetteringOnMessageExpiration", default, skip_serializing_if = "Option::is_none")]
    pub dead_lettering_on_message_expiration: Option<bool>,
    #[serde(rename = "enableBatchedOperations", default, skip_serializing_if = "Option::is_none")]
    pub enable_batched_operations: Option<bool>,
    #[serde(rename = "entityAvailabilityStatus", default, skip_serializing_if = "Option::is_none")]
    pub entity_availability_status: Option<EntityAvailabilityStatus>,
    #[serde(rename = "isReadOnly", default, skip_serializing_if = "Option::is_none")]
    pub is_read_only: Option<bool>,
    #[serde(rename = "lockDuration", default, skip_serializing_if = "Option::is_none")]
    pub lock_duration: Option<String>,
    #[serde(rename = "maxDeliveryCount", default, skip_serializing_if = "Option::is_none")]
    pub max_delivery_count: Option<i32>,
    #[serde(rename = "messageCount", default, skip_serializing_if = "Option::is_none")]
    pub message_count: Option<i64>,
    #[serde(rename = "requiresSession", default, skip_serializing_if = "Option::is_none")]
    pub requires_session: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<EntityStatus>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}
impl SubscriptionProperties {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct SubscriptionResource {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<SubscriptionProperties>,
}
impl SubscriptionResource {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TopicCreateOrUpdateParameters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub location: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<TopicProperties>,
}
impl TopicCreateOrUpdateParameters {
    pub fn new(location: String) -> Self {
        Self {
            name: None,
            location,
            properties: None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct TopicListResult {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<TopicResource>,
    #[serde(rename = "nextLink", default, skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
impl TopicListResult {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct TopicProperties {
    #[serde(rename = "accessedAt", default, skip_serializing_if = "Option::is_none")]
    pub accessed_at: Option<String>,
    #[serde(rename = "autoDeleteOnIdle", default, skip_serializing_if = "Option::is_none")]
    pub auto_delete_on_idle: Option<String>,
    #[serde(rename = "entityAvailabilityStatus", default, skip_serializing_if = "Option::is_none")]
    pub entity_availability_status: Option<EntityAvailabilityStatus>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "countDetails", default, skip_serializing_if = "Option::is_none")]
    pub count_details: Option<MessageCountDetails>,
    #[serde(rename = "defaultMessageTimeToLive", default, skip_serializing_if = "Option::is_none")]
    pub default_message_time_to_live: Option<String>,
    #[serde(rename = "duplicateDetectionHistoryTimeWindow", default, skip_serializing_if = "Option::is_none")]
    pub duplicate_detection_history_time_window: Option<String>,
    #[serde(rename = "enableBatchedOperations", default, skip_serializing_if = "Option::is_none")]
    pub enable_batched_operations: Option<bool>,
    #[serde(rename = "enableExpress", default, skip_serializing_if = "Option::is_none")]
    pub enable_express: Option<bool>,
    #[serde(rename = "enablePartitioning", default, skip_serializing_if = "Option::is_none")]
    pub enable_partitioning: Option<bool>,
    #[serde(rename = "filteringMessagesBeforePublishing", default, skip_serializing_if = "Option::is_none")]
    pub filtering_messages_before_publishing: Option<bool>,
    #[serde(rename = "isAnonymousAccessible", default, skip_serializing_if = "Option::is_none")]
    pub is_anonymous_accessible: Option<bool>,
    #[serde(rename = "isExpress", default, skip_serializing_if = "Option::is_none")]
    pub is_express: Option<bool>,
    #[serde(rename = "maxSizeInMegabytes", default, skip_serializing_if = "Option::is_none")]
    pub max_size_in_megabytes: Option<i64>,
    #[serde(rename = "requiresDuplicateDetection", default, skip_serializing_if = "Option::is_none")]
    pub requires_duplicate_detection: Option<bool>,
    #[serde(rename = "sizeInBytes", default, skip_serializing_if = "Option::is_none")]
    pub size_in_bytes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<EntityStatus>,
    #[serde(rename = "subscriptionCount", default, skip_serializing_if = "Option::is_none")]
    pub subscription_count: Option<i32>,
    #[serde(rename = "supportOrdering", default, skip_serializing_if = "Option::is_none")]
    pub support_ordering: Option<bool>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}
impl TopicProperties {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct TopicResource {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<TopicProperties>,
}
impl TopicResource {
    pub fn new() -> Self {
        Self::default()
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrackedResource {
    #[serde(flatten)]
    pub resource: Resource,
    pub location: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
impl TrackedResource {
    pub fn new(location: String) -> Self {
        Self {
            resource: Resource::default(),
            location,
            tags: None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum UnavailableReason {
    None,
    InvalidName,
    SubscriptionIsDisabled,
    NameInUse,
    NameInLockdown,
    TooManyNamespaceInCurrentSubscription,
}
