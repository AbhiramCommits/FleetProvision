//! SAML 2.0 assertion verification with real XMLDSig validation.
//!
//! The profile is intentionally narrow: one signed Assertion inside a
//! Response, RSA-SHA256 with exclusive C14N, and a groups attribute. Signature
//! verification is delegated to the pure-Rust `xml-sec` implementation.

use roxmltree::Document;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, thiserror::Error)]
pub enum SamlError {
    #[error("SAML XML parse error: {0}")]
    Xml(String),
    #[error("SAML response is unsigned")]
    Unsigned,
    #[error("SAML signature is invalid: {0}")]
    SignatureInvalid(String),
    #[error("SAML reference does not cover the assertion")]
    ReferenceMismatch,
    #[error("SAML destination mismatch: expected {expected}, got {actual}")]
    DestinationMismatch { expected: String, actual: String },
    #[error("SAML audience mismatch: expected {expected}, got {actual}")]
    AudienceMismatch { expected: String, actual: String },
    #[error("SAML issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },
    #[error("SAML assertion is expired")]
    Expired,
    #[error("SAML assertion is not yet valid")]
    NotYetValid,
    #[error("SAML InResponseTo mismatch: expected {expected}, got {actual}")]
    InResponseToMismatch { expected: String, actual: String },
    #[error("SAML assertion was replayed: {0}")]
    Replayed(String),
    #[error("SAML assertion is missing {0}")]
    Missing(&'static str),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamlAssertion {
    pub subject: String,
    pub groups: Vec<String>,
    pub issuer: String,
    pub audience: String,
    pub destination: String,
    pub in_response_to: String,
    pub assertion_id: String,
    pub not_on_or_after: i64,
}

#[derive(Debug, Clone)]
pub struct SamlConfig {
    pub public_key_pem: String,
    pub expected_issuer: String,
    pub audience: String,
    pub destination: String,
    pub clock_skew_seconds: i64,
}

#[derive(Debug, Default)]
pub struct ReplayCache {
    seen: HashSet<String>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SamlConfig {
    pub fn verify(
        &self,
        xml: &str,
        expected_in_response_to: &str,
        replay: &mut ReplayCache,
    ) -> Result<SamlAssertion, SamlError> {
        if !xml.contains("<ds:Signature") && !xml.contains("<Signature") {
            return Err(SamlError::Unsigned);
        }
        let doc = Document::parse(xml).map_err(|e| SamlError::Xml(e.to_string()))?;
        let response = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Response")
            .ok_or_else(|| SamlError::Xml("no Response element".into()))?;
        let assertion = response
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Assertion")
            .ok_or_else(|| SamlError::Xml("no Assertion element".into()))?;
        let assertion_id = assertion
            .attribute("ID")
            .or_else(|| assertion.attribute("Id"))
            .ok_or(SamlError::Missing("Assertion ID"))?
            .to_string();
        let destination = response
            .attribute("Destination")
            .ok_or(SamlError::Missing("Destination"))?
            .to_string();
        let in_response_to = response
            .attribute("InResponseTo")
            .ok_or(SamlError::Missing("InResponseTo"))?
            .to_string();

        let verification =
            xml_sec::xmldsig::verify_signature_with_pem_key(xml, &self.public_key_pem, false)
                .map_err(|e| SamlError::SignatureInvalid(e.to_string()))?;
        if verification.status != xml_sec::xmldsig::DsigStatus::Valid {
            return Err(SamlError::SignatureInvalid(format!(
                "{:?}",
                verification.status
            )));
        }
        let expected_uri = format!("#{assertion_id}");
        let mut covered = false;
        for reference in &verification.signed_info_references {
            if reference.status != xml_sec::xmldsig::DsigStatus::Valid {
                return Err(SamlError::SignatureInvalid(format!(
                    "reference {:?}",
                    reference.status
                )));
            }
            if reference.uri == expected_uri {
                covered = true;
            }
        }
        if !covered {
            return Err(SamlError::ReferenceMismatch);
        }

        if destination != self.destination {
            return Err(SamlError::DestinationMismatch {
                expected: self.destination.clone(),
                actual: destination,
            });
        }
        if in_response_to != expected_in_response_to {
            return Err(SamlError::InResponseToMismatch {
                expected: expected_in_response_to.into(),
                actual: in_response_to.clone(),
            });
        }

        let issuer = assertion
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "Issuer")
            .and_then(|n| n.text())
            .unwrap_or_default()
            .trim()
            .to_string();
        if issuer != self.expected_issuer {
            return Err(SamlError::IssuerMismatch {
                expected: self.expected_issuer.clone(),
                actual: issuer,
            });
        }

        let conditions = assertion
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "Conditions")
            .ok_or(SamlError::Missing("Conditions"))?;
        let not_on_or_after = conditions
            .attribute("NotOnOrAfter")
            .ok_or(SamlError::Missing("NotOnOrAfter"))?;
        let not_on_or_after = OffsetDateTime::parse(not_on_or_after, &Rfc3339)
            .map_err(|e| SamlError::Xml(e.to_string()))?;
        let not_before = conditions
            .attribute("NotBefore")
            .and_then(|v| OffsetDateTime::parse(v, &Rfc3339).ok());
        let now = OffsetDateTime::now_utc();
        if not_on_or_after.unix_timestamp() + self.clock_skew_seconds <= now.unix_timestamp() {
            return Err(SamlError::Expired);
        }
        if let Some(not_before) = not_before {
            if not_before.unix_timestamp() - self.clock_skew_seconds > now.unix_timestamp() {
                return Err(SamlError::NotYetValid);
            }
        }

        let audience = assertion
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Audience")
            .and_then(|n| n.text())
            .unwrap_or_default()
            .trim()
            .to_string();
        if audience != self.audience {
            return Err(SamlError::AudienceMismatch {
                expected: self.audience.clone(),
                actual: audience,
            });
        }

        let subject = assertion
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "NameID")
            .and_then(|n| n.text())
            .unwrap_or_default()
            .trim()
            .to_string();
        if subject.is_empty() {
            return Err(SamlError::Missing("Subject NameID"));
        }

        let mut groups = Vec::new();
        for attribute in assertion
            .descendants()
            .filter(|n| n.is_element() && n.tag_name().name() == "Attribute")
        {
            let name = attribute.attribute("Name").unwrap_or_default();
            if !matches!(name, "groups" | "memberOf" | "roles") {
                continue;
            }
            for value in attribute
                .children()
                .filter(|n| n.is_element() && n.tag_name().name() == "AttributeValue")
            {
                if let Some(text) = value.text() {
                    let text = text.trim();
                    if !text.is_empty() {
                        groups.push(text.to_string());
                    }
                }
            }
        }
        if groups.is_empty() {
            return Err(SamlError::Missing("groups attribute"));
        }

        if !replay.seen.insert(assertion_id.clone()) {
            return Err(SamlError::Replayed(assertion_id));
        }

        Ok(SamlAssertion {
            subject,
            groups,
            issuer,
            audience,
            destination,
            in_response_to,
            assertion_id,
            not_on_or_after: not_on_or_after.unix_timestamp(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn config() -> SamlConfig {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/saml");
        SamlConfig {
            public_key_pem: std::fs::read_to_string(dir.join("idp-public-key.pem")).unwrap(),
            expected_issuer: "https://idp.fleet.internal".into(),
            audience: "fleetd".into(),
            destination: "https://127.0.0.1:9443/v1/saml/acs".into(),
            clock_skew_seconds: 60,
        }
    }

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/saml")
                .join(name),
        )
        .unwrap()
    }

    #[test]
    fn valid_assertion_maps_groups() {
        let mut replay = ReplayCache::new();
        let assertion = config()
            .verify(&fixture("valid.xml"), "req-abc123", &mut replay)
            .unwrap();
        assert_eq!(assertion.subject, "alice@fleet.internal");
        assert_eq!(assertion.groups, vec!["fleet-admin"]);
        assert_eq!(assertion.audience, "fleetd");
    }

    #[test]
    fn replayed_assertion_is_rejected() {
        let mut replay = ReplayCache::new();
        let cfg = config();
        cfg.verify(&fixture("valid.xml"), "req-abc123", &mut replay)
            .unwrap();
        let err = cfg
            .verify(&fixture("replayed.xml"), "req-abc123", &mut replay)
            .unwrap_err();
        assert!(matches!(err, SamlError::Replayed(_)), "{err}");
    }

    #[test]
    fn expired_assertion_is_rejected() {
        let err = config()
            .verify(
                &fixture("expired.xml"),
                "req-abc123",
                &mut ReplayCache::new(),
            )
            .unwrap_err();
        assert!(matches!(err, SamlError::Expired), "{err}");
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let err = config()
            .verify(
                &fixture("wrong-audience.xml"),
                "req-abc123",
                &mut ReplayCache::new(),
            )
            .unwrap_err();
        assert!(matches!(err, SamlError::AudienceMismatch { .. }), "{err}");
    }

    #[test]
    fn unsigned_assertion_is_rejected() {
        let err = config()
            .verify(
                &fixture("unsigned.xml"),
                "req-abc123",
                &mut ReplayCache::new(),
            )
            .unwrap_err();
        assert!(matches!(err, SamlError::Unsigned), "{err}");
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let xml = fixture("valid.xml");
        let marker = "<ds:SignatureValue>";
        let (before, rest) = xml.split_once(marker).unwrap();
        let (_, after) = rest.split_once("</ds:SignatureValue>").unwrap();
        let tampered = format!("{before}{marker}AAAA</ds:SignatureValue>{after}");
        let err = config()
            .verify(&tampered, "req-abc123", &mut ReplayCache::new())
            .unwrap_err();
        assert!(matches!(err, SamlError::SignatureInvalid(_)), "{err}");
    }

    #[test]
    fn wrong_destination_is_rejected() {
        let mut cfg = config();
        cfg.destination = "https://other.example/acs".into();
        let err = cfg
            .verify(&fixture("valid.xml"), "req-abc123", &mut ReplayCache::new())
            .unwrap_err();
        assert!(
            matches!(err, SamlError::DestinationMismatch { .. }),
            "{err}"
        );
    }

    #[test]
    fn wrong_in_response_to_is_rejected() {
        let err = config()
            .verify(&fixture("valid.xml"), "req-other", &mut ReplayCache::new())
            .unwrap_err();
        assert!(
            matches!(err, SamlError::InResponseToMismatch { .. }),
            "{err}"
        );
    }
}
