//! Operator identity: OIDC JWT validation via JWKS with group-based RBAC.

use crate::idp::Claims;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing bearer token")]
    MissingToken,
    #[error("invalid token: {0}")]
    Invalid(String),
    #[error("insufficient group for this operation")]
    Forbidden,
    #[error("identity provider unavailable: {0}")]
    IdpUnavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorClaims {
    pub subject: String,
    pub groups: Vec<String>,
    pub exp: i64,
    pub nonce: Option<String>,
}

impl OperatorClaims {
    pub fn is_admin(&self) -> bool {
        self.groups.iter().any(|g| g == "fleet-admin")
    }

    pub fn is_operator(&self) -> bool {
        self.is_admin() || self.groups.iter().any(|g| g == "fleet-operator")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Read,
    Admin,
}

#[derive(Debug, Clone, Deserialize)]
struct Discovery {
    jwks_uri: String,
}

#[derive(Debug, Clone, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

pub struct JwtValidator {
    issuer: String,
    audience: String,
    client: reqwest::Client,
    cache: Mutex<Option<(JwkSet, Instant)>>,
    cache_ttl: Duration,
}

impl JwtValidator {
    pub fn new(issuer: String, audience: String) -> Self {
        Self {
            issuer,
            audience,
            client: reqwest::Client::new(),
            cache: Mutex::new(None),
            cache_ttl: Duration::from_secs(60),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    async fn jwks(&self) -> Result<JwkSet, AuthError> {
        {
            let cache = self.cache.lock().expect("jwks cache poisoned");
            if let Some((set, at)) = cache.as_ref() {
                if at.elapsed() < self.cache_ttl {
                    return Ok(set.clone());
                }
            }
        }
        let discovery: Discovery = self
            .client
            .get(format!(
                "{}/.well-known/openid-configuration",
                self.issuer.trim_end_matches('/')
            ))
            .send()
            .await
            .map_err(|e| AuthError::IdpUnavailable(e.to_string()))?
            .error_for_status()
            .map_err(|e| AuthError::IdpUnavailable(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::IdpUnavailable(e.to_string()))?;
        let set: JwkSet = self
            .client
            .get(&discovery.jwks_uri)
            .send()
            .await
            .map_err(|e| AuthError::IdpUnavailable(e.to_string()))?
            .error_for_status()
            .map_err(|e| AuthError::IdpUnavailable(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::IdpUnavailable(e.to_string()))?;
        *self.cache.lock().expect("jwks cache poisoned") = Some((set.clone(), Instant::now()));
        Ok(set)
    }

    pub async fn validate(&self, token: &str) -> Result<OperatorClaims, AuthError> {
        let header =
            decode_header(token).map_err(|e| AuthError::Invalid(format!("header: {e}")))?;
        if header.alg != Algorithm::RS256 {
            return Err(AuthError::Invalid("algorithm is not RS256".into()));
        }
        let kid = header
            .kid
            .ok_or_else(|| AuthError::Invalid("missing kid".into()))?;
        let keys = self.jwks().await?;
        let jwk = keys
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .ok_or_else(|| AuthError::Invalid(format!("unknown kid {kid}")))?;
        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| AuthError::Invalid(format!("jwk: {e}")))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.leeway = 30;
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);
        let data = decode::<Claims>(token, &key, &validation)
            .map_err(|e| AuthError::Invalid(e.to_string()))?;
        let groups = data.claims.groups.clone();
        if !groups
            .iter()
            .any(|g| g == "fleet-admin" || g == "fleet-operator")
        {
            return Err(AuthError::Forbidden);
        }
        Ok(OperatorClaims {
            subject: data.claims.sub,
            groups,
            exp: data.claims.exp,
            nonce: data.claims.nonce,
        })
    }

    pub async fn authorize(
        &self,
        headers: &axum::http::HeaderMap,
        role: Role,
    ) -> Result<OperatorClaims, AuthError> {
        let token = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AuthError::MissingToken)?;
        let claims = self.validate(token).await?;
        match role {
            Role::Read if claims.is_operator() => Ok(claims),
            Role::Admin if claims.is_admin() => Ok(claims),
            _ => Err(AuthError::Forbidden),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idp::{start, RunningIdp};

    async fn setup() -> (RunningIdp, JwtValidator) {
        let idp = start().await.unwrap();
        let validator = JwtValidator::new(idp.issuer.clone(), "fleetd".into());
        (idp, validator)
    }

    #[tokio::test]
    async fn valid_token_yields_groups_and_nonce() {
        let (idp, validator) = setup().await;
        let token = idp.sign_token(
            "alice",
            vec!["fleet-admin".into()],
            "fleetd",
            60,
            &idp.kid,
            Some("n-1".into()),
        );
        let claims = validator.validate(&token).await.unwrap();
        assert_eq!(claims.subject, "alice");
        assert!(claims.is_admin());
        assert_eq!(claims.nonce.as_deref(), Some("n-1"));
        idp.shutdown().await;
    }

    #[tokio::test]
    async fn operator_cannot_perform_admin_actions() {
        let (idp, validator) = setup().await;
        let token = idp.sign_token(
            "bob",
            vec!["fleet-operator".into()],
            "fleetd",
            60,
            &idp.kid,
            None,
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        assert!(validator.authorize(&headers, Role::Read).await.is_ok());
        assert!(matches!(
            validator.authorize(&headers, Role::Admin).await,
            Err(AuthError::Forbidden)
        ));
        idp.shutdown().await;
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let (idp, validator) = setup().await;
        let token = idp.sign_token(
            "alice",
            vec!["fleet-admin".into()],
            "fleetd",
            -3600,
            &idp.kid,
            None,
        );
        assert!(matches!(
            validator.validate(&token).await,
            Err(AuthError::Invalid(_))
        ));
        idp.shutdown().await;
    }

    #[tokio::test]
    async fn wrong_audience_is_rejected() {
        let (idp, validator) = setup().await;
        let token = idp.sign_token(
            "alice",
            vec!["fleet-admin".into()],
            "some-other-service",
            60,
            &idp.kid,
            None,
        );
        assert!(validator.validate(&token).await.is_err());
        idp.shutdown().await;
    }

    #[tokio::test]
    async fn unknown_kid_is_rejected() {
        let (idp, validator) = setup().await;
        let token = idp.sign_token(
            "alice",
            vec!["fleet-admin".into()],
            "fleetd",
            60,
            "unknown-key",
            None,
        );
        let err = validator.validate(&token).await.unwrap_err();
        assert!(err.to_string().contains("unknown kid"), "{err}");
        idp.shutdown().await;
    }

    #[tokio::test]
    async fn tampered_signature_is_rejected() {
        let (idp, validator) = setup().await;
        let token = idp.sign_token(
            "alice",
            vec!["fleet-admin".into()],
            "fleetd",
            60,
            &idp.kid,
            None,
        );
        let mut parts: Vec<String> = token.split('.').map(|s| s.to_string()).collect();
        let sig = parts[2].as_bytes().to_vec();
        let mut sig: Vec<u8> = sig;
        sig[0] = if sig[0] == b'A' { b'B' } else { b'A' };
        parts[2] = String::from_utf8(sig).unwrap();
        let tampered = parts.join(".");
        assert!(validator.validate(&tampered).await.is_err());
        idp.shutdown().await;
    }

    #[tokio::test]
    async fn insufficient_group_is_forbidden() {
        let (idp, validator) = setup().await;
        let token = idp.sign_token(
            "mallory",
            vec!["some-other-group".into()],
            "fleetd",
            60,
            &idp.kid,
            None,
        );
        assert!(matches!(
            validator.validate(&token).await,
            Err(AuthError::Forbidden)
        ));
        idp.shutdown().await;
    }
}
