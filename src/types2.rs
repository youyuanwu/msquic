use std::ffi::CString;

use crate::ffi::{QUIC_CREDENTIAL_CONFIG, QUIC_REGISTRATION_CONFIG};

/// Specifies the configuration for a new registration.
#[derive(Debug, Default)]
pub struct RegistrationConfig {
    app_name: Option<CString>,
    execution_profile: ExecutionProfile,
}

impl RegistrationConfig {
    pub fn as_ffi(&self) -> QUIC_REGISTRATION_CONFIG {
        QUIC_REGISTRATION_CONFIG {
            AppName: self
                .app_name
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(std::ptr::null()),
            ExecutionProfile: self.execution_profile.clone().into(),
        }
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_app_name(mut self, value: String) -> Self {
        self.app_name = Some(CString::new(value.as_bytes()).unwrap());
        self
    }

    pub fn set_execution_profile(mut self, value: ExecutionProfile) -> Self {
        self.execution_profile = value;
        self
    }
}

/// Configures how to process a registration's workload.
#[derive(Debug, PartialEq, Clone)]
pub enum ExecutionProfile {
    LowLatency,
    MaxThroughput,
    Scavenger,
    RealTime,
}

impl Default for ExecutionProfile {
    fn default() -> Self {
        Self::LowLatency
    }
}

impl From<ExecutionProfile> for crate::ffi::QUIC_EXECUTION_PROFILE {
    fn from(value: ExecutionProfile) -> Self {
        match value {
            ExecutionProfile::LowLatency => {
                crate::ffi::QUIC_EXECUTION_PROFILE_QUIC_EXECUTION_PROFILE_LOW_LATENCY
            }
            ExecutionProfile::MaxThroughput => {
                crate::ffi::QUIC_EXECUTION_PROFILE_QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT
            }
            ExecutionProfile::Scavenger => {
                crate::ffi::QUIC_EXECUTION_PROFILE_QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER
            }
            ExecutionProfile::RealTime => {
                crate::ffi::QUIC_EXECUTION_PROFILE_QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct CredentialConfig {
    credential_flags: CredentialFlags,
    credential: Credential,
    principle: Option<CString>, // TODO: support async handler.
    allowed_cipher_suites: AllowedCipherSuiteFlags,
    ca_certificate_file: Option<CString>,
}

impl CredentialConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// flags are additive when called multiple times.
    pub fn set_credential_flags(mut self, value: CredentialFlags) -> Self {
        self.credential_flags |= value;
        self
    }

    pub fn set_credential(mut self, value: Credential) -> Self {
        self.credential = value;
        self
    }

    pub fn set_principle(mut self, value: String) -> Self {
        self.principle = Some(CString::new(value.as_bytes()).unwrap());
        self
    }

    pub fn set_allowed_cipher_suites(mut self, value: AllowedCipherSuiteFlags) -> Self {
        self.credential_flags |= CredentialFlags::SET_ALLOWED_CIPHER_SUITES;
        self.allowed_cipher_suites = value;
        self
    }

    pub fn set_ca_certificate_file(mut self, value: String) -> Self {
        self.credential_flags |= CredentialFlags::SET_CA_CERTIFICATE_FILE;
        self.ca_certificate_file = Some(CString::new(value.as_bytes()).unwrap());
        self
    }

    // TODO: support all types.
    /// Currently only hash and file types are supported.
    pub fn as_ffi(&self) -> QUIC_CREDENTIAL_CONFIG {
        let mut ffi_cfg = unsafe { std::mem::zeroed::<QUIC_CREDENTIAL_CONFIG>() };
        ffi_cfg.Flags = self.credential_flags.bits();
        match &self.credential {
            Credential::None => {}
            Credential::CertificateHash(hash) => {
                ffi_cfg.Type =
                    crate::ffi::QUIC_CREDENTIAL_TYPE_QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
                ffi_cfg.__bindgen_anon_1.CertificateHash = (&hash.0) as *const _ as *mut _;
            }
            Credential::CertificateHashStore => todo!(),
            Credential::CertificateContext => todo!(),
            Credential::CertificateFile(file) => {
                ffi_cfg.Type =
                    crate::ffi::QUIC_CREDENTIAL_TYPE_QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
                ffi_cfg.__bindgen_anon_1.CertificateFile = file.as_ffi_ref() as *const _ as *mut _;
            }
            Credential::CertificateFileProtected => todo!(),
            Credential::CertificatePkcs12 => todo!(),
        }
        ffi_cfg.Principal = self
            .principle
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null());
        ffi_cfg.AllowedCipherSuites = self.allowed_cipher_suites.bits();
        ffi_cfg.CaCertificateFile = self
            .ca_certificate_file
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null());
        ffi_cfg
    }

    pub fn new_client() -> Self {
        Self::default()
            .set_credential_flags(CredentialFlags::CLIENT)
            .set_credential(Credential::None)
    }
}

#[derive(Debug)]
pub struct CertificateHash(pub crate::ffi::QUIC_CERTIFICATE_HASH);
impl CertificateHash {
    pub fn new(hash: [u8; 20usize]) -> Self {
        Self(crate::ffi::QUIC_CERTIFICATE_HASH { ShaHash: hash })
    }
}

#[derive(Debug)]
pub struct CertificateFile {
    raw: crate::ffi::QUIC_CERTIFICATE_FILE,
    _private_key_file: CString,
    _certificate_file: CString,
}

impl CertificateFile {
    pub fn new(private_key_file: String, certificate_file: String) -> Self {
        let key = CString::new(private_key_file.as_bytes()).unwrap();
        let cert = CString::new(certificate_file.as_bytes()).unwrap();
        Self {
            raw: crate::ffi::QUIC_CERTIFICATE_FILE {
                PrivateKeyFile: key.as_ptr(),
                CertificateFile: cert.as_ptr(),
            },
            _private_key_file: key,
            _certificate_file: cert,
        }
    }

    pub fn as_ffi_ref(&self) -> &crate::ffi::QUIC_CERTIFICATE_FILE {
        &self.raw
    }
}

// TODO: support all cred types.
/// Type of credentials used for a connection.
#[derive(Debug)]
pub enum Credential {
    None,
    CertificateHash(CertificateHash),
    CertificateHashStore,
    CertificateContext,
    CertificateFile(CertificateFile),
    CertificateFileProtected,
    CertificatePkcs12,
}

impl Default for Credential {
    fn default() -> Self {
        Self::None
    }
}

bitflags::bitflags! {
/// Modifies the default credential configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialFlags: crate::ffi::QUIC_CREDENTIAL_FLAGS {
  const NONE = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_NONE;
  const CLIENT = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_CLIENT;
  const LOAD_ASYNCHRONOUS = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS;
  const NO_CERTIFICATE_VALIDATION = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
  const ENABLE_OCSP = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_ENABLE_OCSP;
  const INDICATE_CERTIFICATE_RECEIVED = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
  const DEFER_CERTIFICATE_VALIDATION = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION;
  const REQUIRE_CLIENT_AUTHENTICATION = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION;
  const USE_TLS_BUILTIN_CERTIFICATE_VALIDATION = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION;
  const REVOCATION_CHECK_END_CERT = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT;
  const REVOCATION_CHECK_CHAIN = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN;
  const REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
  const IGNORE_NO_REVOCATION_CHECK = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK;
  const IGNORE_REVOCATION_OFFLINE = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE;
  const SET_ALLOWED_CIPHER_SUITES = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES;
  const USE_PORTABLE_CERTIFICATES = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES;
  const USE_SUPPLIED_CREDENTIALS = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS;
  const USE_SYSTEM_MAPPER = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_USE_SYSTEM_MAPPER;
  const CACHE_ONLY_URL_RETRIEVAL = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL;
  const REVOCATION_CHECK_CACHE_ONLY = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY;
  const INPROC_PEER_CERTIFICATE = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_INPROC_PEER_CERTIFICATE;
  const SET_CA_CERTIFICATE_FILE = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
  const DISABLE_AIA = crate::ffi::QUIC_CREDENTIAL_FLAGS_QUIC_CREDENTIAL_FLAG_DISABLE_AIA;
  // reject undefined flags.
  const _ = !0;
  }
}

impl Default for CredentialFlags {
    fn default() -> Self {
        Self::NONE
    }
}

bitflags::bitflags! {
  /// Set of allowed TLS cipher suites.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub struct AllowedCipherSuiteFlags: crate::ffi::QUIC_ALLOWED_CIPHER_SUITE_FLAGS {
    const NONE = crate::ffi::QUIC_ALLOWED_CIPHER_SUITE_FLAGS_QUIC_ALLOWED_CIPHER_SUITE_NONE;
    const AES_128_GCM_SHA256 = crate::ffi::QUIC_ALLOWED_CIPHER_SUITE_FLAGS_QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256;
    const AES_256_GCM_SHA384 = crate::ffi::QUIC_ALLOWED_CIPHER_SUITE_FLAGS_QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384;
    const CHACHA20_POLY1305_SHA256  = crate::ffi::QUIC_ALLOWED_CIPHER_SUITE_FLAGS_QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256;
    // reject undefined flags.
    const _ = !0;
  }
}

impl Default for AllowedCipherSuiteFlags {
    fn default() -> Self {
        Self::NONE
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        types2::{CertificateFile, CertificateHash, Credential},
        Buffer, Configuration, Registration, RegistrationConfig, Settings, StatusCode,
    };

    use super::CredentialConfig;

    #[test]
    fn config_load() {
        let registration = Registration::new(&RegistrationConfig::default()).unwrap();

        let alpn = [Buffer::from("h3")];
        let configuration = Configuration::new(
            &registration,
            &alpn,
            Settings::new()
                .set_peer_bidi_stream_count(100)
                .set_peer_unidi_stream_count(3),
        )
        .unwrap();

        {
            let cred_config =
                CredentialConfig::new().set_credential_flags(super::CredentialFlags::NONE);
            // server cred missing
            assert_eq!(
                configuration
                    .load_credential(&cred_config)
                    .unwrap_err()
                    .try_as_status_code()
                    .unwrap(),
                StatusCode::QUIC_STATUS_INVALID_PARAMETER
            );
            // openssl does not support hash, or hash is empty and cert not found
            let cred_config = cred_config
                .set_credential(Credential::CertificateHash(CertificateHash::new([0; 20])));
            assert_eq!(
                configuration
                    .load_credential(&cred_config)
                    .unwrap_err()
                    .try_as_status_code()
                    .unwrap(),
                StatusCode::QUIC_STATUS_NOT_FOUND
            );
            // key and cert file not found
            let cred_config = cred_config.set_credential(Credential::CertificateFile(
                CertificateFile::new(String::from("./no_key"), String::from("./no_cert")),
            ));
            assert_eq!(
                configuration
                    .load_credential(&cred_config)
                    .unwrap_err()
                    .try_as_status_code()
                    .unwrap(),
                StatusCode::QUIC_STATUS_TLS_ERROR
            );
        }
    }
}
