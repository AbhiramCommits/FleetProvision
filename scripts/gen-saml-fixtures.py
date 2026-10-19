#!/usr/bin/env python3
"""Generate signed SAML 2.0 fixture assertions for FleetProvision tests.

Requires: pip install signxml cryptography
Fixes the IdP key material and assertion shape; re-running changes signatures
and is not required. The committed fixtures are the test inputs.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner, methods

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "saml"
OUT.mkdir(parents=True, exist_ok=True)

DESTINATION = "https://127.0.0.1:9443/v1/saml/acs"
ISSUER = "https://idp.fleet.internal"
AUDIENCE = "fleetd"
IN_RESPONSE_TO = "req-abc123"


def make_key_and_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "FleetProvision Mock SAML IdP")]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    (OUT / "idp-key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (OUT / "idp-cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (OUT / "idp-public-key.pem").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return key, cert


def assertion(
    assertion_id,
    *,
    audience=AUDIENCE,
    not_before="2020-01-01T00:00:00Z",
    not_on_or_after="2035-01-01T00:00:00Z",
    groups=("fleet-admin",),
    signed=True,
    key=None,
    cert=None,
):
    attr_values = "".join(f"<saml:AttributeValue>{g}</saml:AttributeValue>" for g in groups)
    xml = f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" IssueInstant="2026-01-01T00:00:00Z" Version="2.0">
  <saml:Issuer>{ISSUER}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@fleet.internal</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" Recipient="{DESTINATION}" InResponseTo="{IN_RESPONSE_TO}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
    <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z" SessionIndex="_session-1">
    <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name="groups" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">{attr_values}</saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>"""
    if not signed:
        return xml
    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    signed = signer.sign(etree.fromstring(xml.encode()), key=key, cert=[cert], reference_uri=assertion_id)
    return etree.tostring(signed, encoding="unicode")


def response(assertion_xml, response_id="_resp-1"):
    return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="{DESTINATION}" ID="{response_id}" InResponseTo="{IN_RESPONSE_TO}" IssueInstant="2026-01-01T00:00:00Z" Version="2.0">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{ISSUER}</saml:Issuer>
  {assertion_xml}
</samlp:Response>"""


def main():
    key, cert = make_key_and_cert()
    valid = assertion("_assert-valid", key=key, cert=cert)
    (OUT / "valid.xml").write_text(response(valid))
    (OUT / "replayed.xml").write_text(response(valid, response_id="_resp-replayed"))
    expired = assertion(
        "_assert-expired",
        not_before="2018-01-01T00:00:00Z",
        not_on_or_after="2020-01-01T00:00:00Z",
        key=key,
        cert=cert,
    )
    (OUT / "expired.xml").write_text(response(expired, response_id="_resp-expired"))
    wrong = assertion("_assert-wrong-aud", audience="another-service", key=key, cert=cert)
    (OUT / "wrong-audience.xml").write_text(response(wrong, response_id="_resp-wrong"))
    unsigned = assertion("_assert-unsigned", signed=False)
    (OUT / "unsigned.xml").write_text(response(unsigned, response_id="_resp-unsigned"))
    print(f"wrote SAML fixtures to {OUT}")


if __name__ == "__main__":
    main()
