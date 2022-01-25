use std::fmt::{Debug, Display};

use crate::sync::TokenCredential;
use base64::{CharacterSet, Config};
use chrono::serde::ts_seconds_option;
use chrono::{DateTime, Utc};
use getset::Getters;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::sync::API_VERSION_PARAM;
use crate::Error;
use crate::sync::KeyClient;

/// A KeyBundle consisting of a WebKey plus its attributes.
#[derive(Debug, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct KeyVaultKey {
    /// The key management properties.
    #[serde(flatten)]
    properties: KeyProperties,
    /// The Json web key.
    key: JsonWebKey,
}

#[derive(Debug, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct KeyProperties {
    attributes: KeyAttributes,
    /// True if the key's lifetime is managed by key vault. If this is a key backing a certificate, then managed will be true.
    managed: Option<bool>,
    /// Application specific metadata in the form of key-value pairs.
    tags: Option<Map<String, Value>>,
}

#[derive(Debug, Deserialize, Getters)]
#[getset(get = "pub")]
#[serde(rename_all = "camelCase")]
pub struct KeyAttributes {
    /// Creation time in UTC.
    #[serde(rename = "created", with = "ts_seconds_option", default)]
    created_on: Option<DateTime<Utc>>,
    /// Determines whether the object is enabled.
    enabled: Option<bool>,
    /// Expiry date in UTC.
    #[serde(rename = "exp", with = "ts_seconds_option", default)]
    expires_on: Option<DateTime<Utc>>,
    /// Not before date in UTC.
    #[serde(rename = "nbf", with = "ts_seconds_option", default)]
    not_before: Option<DateTime<Utc>>,
    /// softDelete data retention days. Value should be >=7 and <=90 when softDelete enabled, otherwise 0.
    recoverable_days: Option<u8>,
    /// Reflects the deletion recovery level currently in effect for keys in the current vault. If it contains 'Purgeable' the key can be permanently deleted by a privileged user; otherwise, only the system can purge the key, at the end of the retention interval.
    recovery_level: Option<String>,
    /// Last updated time in UTC.
    #[serde(rename = "updated", with = "ts_seconds_option", default)]
    updated_on: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct JsonWebKey {
    /// Elliptic curve name. For valid values, see JsonWebKeyCurveName.
    #[serde(rename = "crv")]
    curve_name: Option<String>,
    /// RSA private exponent, or the D component of an EC private key.
    #[serde(
    serialize_with = "ser_base64_opt",
    deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    d: Option<Vec<u8>>,
    /// RSA private key parameter.
    #[serde(
    serialize_with = "ser_base64_opt",
    deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    dp: Option<Vec<u8>>,
    /// RSA private key parameter.
    #[serde(
    serialize_with = "ser_base64_opt",
    deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    dq: Option<Vec<u8>>,
    /// RSA public exponent.
    #[serde(
    serialize_with = "ser_base64_opt",
    deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    e: Option<Vec<u8>>,
    /// Symmetric key.
    #[serde(
    serialize_with = "ser_base64_opt",
    deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    k: Option<Vec<u8>>,
    /// HSM Token, used with 'Bring Your Own Key'.
    #[serde(
    serialize_with = "ser_base64_opt",
    deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    #[serde(rename = "key_hsm")]
    t: Option<Vec<u8>>,
    /// Supported key operations.
    key_ops: Option<Vec<String>>,
    /// Key identifier.
    #[serde(rename = "kid")]
    id: Option<String>,
    /// JsonWebKey Key Type (kty), as defined in <https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40>.
    #[serde(rename = "kty")]
    key_type: String,
    /// RSA modulus.
    #[serde(
    serialize_with = "ser_base64_opt",
    deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    n: Option<Vec<u8>>,
    /// RSA secret prime.
    #[serde(
    serialize_with = "ser_base64_opt",
    deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    p: Option<Vec<u8>>,
    /// RSA secret prime, with p < q.
    #[serde(
    serialize_with = "ser_base64_opt",
    deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    q: Option<Vec<u8>>,
    /// RSA private key parameter.
    #[serde(
    serialize_with = "ser_base64_opt",
    deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    qi: Option<Vec<u8>>,
    /// X component of an EC public key.
    #[serde(
    serialize_with = "ser_base64_opt",
    deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    x: Option<Vec<u8>>,
    /// Y component of an EC public key.
    #[serde(
    serialize_with = "ser_base64_opt",
    deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    y: Option<Vec<u8>>,
}

const BASE64_URL_SAFE: Config = Config::new(CharacterSet::UrlSafe, false);

fn ser_base64<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
{
    let base_64 = base64::encode_config(bytes, BASE64_URL_SAFE);
    serializer.serialize_str(&base_64)
}

fn ser_base64_opt<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
{
    if let Some(bytes) = bytes {
        let base_64 = base64::encode_config(bytes, BASE64_URL_SAFE);
        serializer.serialize_str(&base_64)
    } else {
        serializer.serialize_none()
    }
}

fn deser_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    let res = base64::decode_config(s, BASE64_URL_SAFE).map_err(serde::de::Error::custom)?;
    Ok(res)
}

fn deser_base64_opt<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
{
    let s: Option<&str> = Option::deserialize(deserializer)?;
    let res = match s {
        Some(s) => {
            Some(base64::decode_config(s, BASE64_URL_SAFE).map_err(serde::de::Error::custom)?)
        }
        None => None,
    };
    Ok(res)
}

#[derive(Debug, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct SignResult {
    #[serde(
    rename = "value",
    serialize_with = "ser_base64",
    deserialize_with = "deser_base64"
    )]
    signature: Vec<u8>,
    #[serde(skip)]
    algorithm: SignatureAlgorithm,
    #[serde(rename = "kid")]
    key_id: String,
}

/// The signing/verification algorithm identifier
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SignatureAlgorithm {
    ES256,  // ECDSA using P-256 and SHA-256, as described in https://tools.ietf.org/html/rfc7518.
    ES256K, // ECDSA using P-256K and SHA-256, as described in https://tools.ietf.org/html/rfc7518
    ES384,  // ECDSA using P-384 and SHA-384, as described in https://tools.ietf.org/html/rfc7518
    ES512,  // ECDSA using P-521 and SHA-512, as described in https://tools.ietf.org/html/rfc7518
    PS256, // RSASSA-PSS using SHA-256 and MGF1 with SHA-256, as described in https://tools.ietf.org/html/rfc7518
    PS384, // RSASSA-PSS using SHA-384 and MGF1 with SHA-384, as described in https://tools.ietf.org/html/rfc7518
    PS512, // RSASSA-PSS using SHA-512 and MGF1 with SHA-512, as described in https://tools.ietf.org/html/rfc7518
    RS256, // RSASSA-PKCS1-v1_5 using SHA-256, as described in https://tools.ietf.org/html/rfc7518
    RS384, // RSASSA-PKCS1-v1_5 using SHA-384, as described in https://tools.ietf.org/html/rfc7518
    RS512, // RSASSA-PKCS1-v1_5 using SHA-512, as described in https://tools.ietf.org/html/rfc7518
    Custom(String),
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        SignatureAlgorithm::Custom("".to_string())
    }
}

impl Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    #[serde(rename = "A128CBC")]
    A128Cbc,
    #[serde(rename = "A128CBCPAD")]
    A128CbcPad,
    #[serde(rename = "A128GCM")]
    A128Gcm,
    #[serde(rename = "A192CBC")]
    A192Cbc,
    #[serde(rename = "A192CBCPAD")]
    A192CbcPad,
    #[serde(rename = "A192GCM")]
    A192Gcm,
    #[serde(rename = "A256CBC")]
    A256Cbc,
    #[serde(rename = "A256CBCPAD")]
    A256CbcPad,
    #[serde(rename = "A256GCM")]
    A256Gcm,
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
    #[serde(rename = "RSA1_5")]
    Rsa15,
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        EncryptionAlgorithm::A128Cbc
    }
}

impl Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptParameters {
    pub decrypt_parameters_encryption: DecryptParametersEncryption,
    #[serde(serialize_with = "ser_base64", deserialize_with = "deser_base64")]
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DecryptParametersEncryption {
    Rsa(RsaDecryptParameters),
    AesGcm(AesGcmDecryptParameters),
    AesCbc(AesCbcDecryptParameters),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RsaDecryptParameters {
    algorithm: EncryptionAlgorithm,
}

impl RsaDecryptParameters {
    pub fn new(algorithm: EncryptionAlgorithm) -> Result<Self, Error> {
        match algorithm {
            EncryptionAlgorithm::Rsa15
            | EncryptionAlgorithm::RsaOaep
            | EncryptionAlgorithm::RsaOaep256 => Ok(Self { algorithm }),
            _ => Err(Error::EncryptionAlgorithmMismatch),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AesGcmDecryptParameters {
    algorithm: EncryptionAlgorithm,
    #[serde(serialize_with = "ser_base64", deserialize_with = "deser_base64")]
    pub iv: Vec<u8>,
    #[serde(serialize_with = "ser_base64", deserialize_with = "deser_base64")]
    pub authentication_tag: Vec<u8>,
    #[serde(
    serialize_with = "ser_base64_opt",
    deserialize_with = "deser_base64_opt"
    )]
    pub additional_authenticated_data: Option<Vec<u8>>,
}

impl AesGcmDecryptParameters {
    pub fn new(
        algorithm: EncryptionAlgorithm,
        iv: Vec<u8>,
        authentication_tag: Vec<u8>,
        additional_authenticated_data: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        match algorithm {
            EncryptionAlgorithm::A128Gcm
            | EncryptionAlgorithm::A192Gcm
            | EncryptionAlgorithm::A256Gcm => Ok(Self {
                algorithm,
                iv,
                authentication_tag,
                additional_authenticated_data,
            }),
            _ => Err(Error::EncryptionAlgorithmMismatch),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AesCbcDecryptParameters {
    algorithm: EncryptionAlgorithm,
    #[serde(serialize_with = "ser_base64", deserialize_with = "deser_base64")]
    pub iv: Vec<u8>,
}

impl AesCbcDecryptParameters {
    pub fn new(algorithm: EncryptionAlgorithm, iv: Vec<u8>) -> Result<Self, Error> {
        match algorithm {
            EncryptionAlgorithm::A128Cbc
            | EncryptionAlgorithm::A192Cbc
            | EncryptionAlgorithm::A256Cbc
            | EncryptionAlgorithm::A128CbcPad
            | EncryptionAlgorithm::A192CbcPad
            | EncryptionAlgorithm::A256CbcPad => Ok(Self { algorithm, iv }),
            _ => Err(Error::EncryptionAlgorithmMismatch),
        }
    }
}

#[derive(Debug, Deserialize, Getters)]
#[getset(get = "pub")]
pub struct DecryptResult {
    #[serde(skip)]
    algorithm: EncryptionAlgorithm,
    #[serde(rename = "kid")]
    key_id: String,
    #[serde(
    rename = "value",
    serialize_with = "ser_base64",
    deserialize_with = "deser_base64"
    )]
    result: Vec<u8>,
}

impl<'a, T: TokenCredential> KeyClient<'a, T> {
    /// Gets the public part of a stored key.
    /// The get key operation is applicable to all key types.
    /// If the requested key is symmetric, then no key material is released in the response.
    /// This operation requires the keys/get permission.
    ///
    /// GET {vaultBaseUrl}/keys/{key-name}/{key-version}?api-version=7.1
    pub fn get_key(
        &mut self,
        key_name: &str,
        key_version: Option<&str>,
    ) -> Result<KeyVaultKey, Error> {
        let mut uri = self.vault_url.clone();
        let path = if let Some(ver) = key_version {
            format!("keys/{}/{}", key_name, ver)
        } else {
            format!("keys/{}", key_name)
        };
        uri.set_path(&path);
        uri.set_query(Some(API_VERSION_PARAM));

        let resp_body = self.get_authed(uri.to_string())?;
        let response = serde_json::from_str::<KeyVaultKey>(&resp_body)?;
        Ok(response)
    }

    /// Creates a signature from a digest using the specified key.
    /// The SIGN operation is applicable to asymmetric and symmetric keys stored in Azure Key Vault since this operation uses the private portion of the key.
    /// This operation requires the keys/sign permission.
    pub fn sign(
        &mut self,
        algorithm: SignatureAlgorithm,
        key_name: &str,
        key_version: &str,
        digest: &str,
    ) -> Result<SignResult, Error> {
        // POST {vaultBaseUrl}/keys/{key-name}/{key-version}/sign?api-version=7.1

        let mut uri = self.vault_url.clone();
        uri.set_path(&format!("keys/{}/{}/sign", key_name, key_version));
        uri.set_query(Some(API_VERSION_PARAM));

        let mut request_body = Map::new();
        request_body.insert("alg".to_owned(), Value::String(algorithm.to_string()));
        request_body.insert("value".to_owned(), Value::String(digest.to_owned()));

        let response = self
            .post_authed(
                uri.to_string(),
                Some(Value::Object(request_body).to_string()),
            )?;

        let mut result = serde_json::from_str::<SignResult>(&response)?;
        result.algorithm = algorithm;
        Ok(result)
    }

    /// Decrypt a single block of encrypted data.
    /// The DECRYPT operation decrypts a well-formed block of ciphertext using the target encryption key and specified algorithm.
    /// This operation is the reverse of the ENCRYPT operation; only a single block of data may be decrypted, the size of this block is dependent on the target key and the algorithm to be used.
    /// The DECRYPT operation applies to asymmetric and symmetric keys stored in Vault or HSM since it uses the private portion of the key. This operation requires the keys/decrypt permission.
    pub fn decrypt(
        &mut self,
        key_name: &str,
        key_version: Option<&str>,
        decrypt_parameters: DecryptParameters,
    ) -> Result<DecryptResult, Error> {
        // POST {vaultBaseUrl}/keys/{key-name}/{key-version}/decrypt?api-version=7.2

        let mut uri = self.vault_url.clone();
        let path = format!("keys/{}/{}/decrypt", key_name, key_version.unwrap_or(""));

        uri.set_path(&path);
        uri.set_query(Some(API_VERSION_PARAM));

        let mut request_body = Map::new();
        request_body.insert(
            "value".to_owned(),
            Value::String(base64::encode(decrypt_parameters.ciphertext.to_owned())),
        );

        let algorithm = match decrypt_parameters.decrypt_parameters_encryption {
            DecryptParametersEncryption::Rsa(RsaDecryptParameters { algorithm }) => {
                request_body.insert("alg".to_owned(), serde_json::to_value(&algorithm).unwrap());
                algorithm
            }
            DecryptParametersEncryption::AesGcm(AesGcmDecryptParameters {
                                                    algorithm,
                                                    iv,
                                                    authentication_tag,
                                                    additional_authenticated_data,
                                                }) => {
                request_body.insert("alg".to_owned(), serde_json::to_value(&algorithm).unwrap());
                request_body.insert("iv".to_owned(), serde_json::to_value(iv).unwrap());
                request_body.insert(
                    "tag".to_owned(),
                    serde_json::to_value(authentication_tag).unwrap(),
                );
                if let Some(aad) = additional_authenticated_data {
                    request_body.insert("aad".to_owned(), serde_json::to_value(aad).unwrap());
                };
                algorithm
            }
            DecryptParametersEncryption::AesCbc(AesCbcDecryptParameters { algorithm, iv }) => {
                request_body.insert("alg".to_owned(), serde_json::to_value(&algorithm).unwrap());
                request_body.insert("iv".to_owned(), serde_json::to_value(iv).unwrap());
                algorithm
            }
        };

        let response = self
            .post_authed(
                uri.to_string(),
                Some(Value::Object(request_body).to_string()),
            )?;

        let mut result = serde_json::from_str::<DecryptResult>(&response)?;
        result.algorithm = algorithm;
        Ok(result)
    }
}
