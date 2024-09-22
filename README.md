![Maven Central Version](https://img.shields.io/maven-central/v/com.elevenware.quickpki/quickpki-core?color=#008000)

# Quick Pki

Quick Pki is a Java library aimed at providing a small implementation of a Public Key Infrastructure (PKI) for use
in unit testing and other scenarios where one needs to generate certificates and keys quickly and easily without relying
on a full-blown PKI, or including in test code, real certificates which will eventually expire.

##
Downloading

The latest version of QuickPki can be downloaded from Maven Central. 

```xml
<dependency>
    <groupId>com.elevenware.quickpki</groupId>
    <artifactId>quickpki-core</artifactId>
    <version>0.0.2</version>
</dependency> 
```

Using gradle 
    
```groovy
implementation 'com.elevenware:quickpki:quickpi-core:0.0.2'
```

## Usage

QuickPki aims to be useable with minimal configuration. The following example demonstrates how to issue a certificate and 
verify it against the issuer.

```java
@Test
void createCertificate() throws Exception {
    // Create a new PKI
    QuickPki pki = QuickPki.createDefault();
    CertificateBundle issuer = pki.getIssuer();
    
    // Create a new certificate
    CertificateBundle certificate = pki.issueCertificate(CertInfo.builder()
            .subject(SubjectName.builder()
                    .commonName("Leaf Certificate")
                    .build())
            .build());
    assertEquals("Leaf Certificate", bundle.getCommonName());
    assertTrue(bundle.issuedBy(issuer));
}
```

By default, a new certificate will be created valid from the time of creation, for one day. This can be changed thus:

```java
@Test
void createCertificateWithCustomExpiry() throws Exception {
    QuickPki pki = QuickPki.createDefault();
    CertificateBundle issuer = pki.getIssuer();
    
    CertificateBundle certificate = pki.issueCertificate(CertInfo.builder()
            .subject(SubjectName.builder()
                    .commonName("Leaf Certificate")
                    .build())
            .validFrom(Instant.now().minus(2, ChronoUnit.HOURS))
            .validUntil(Instant.now().minus(1, ChronoUnit.HOURS))
            .build());
    assertThrows(CertificateExpiredException.class, () -> certificate.getCertificate().checkValidity());
}
```

### Customising the PKI

The class com.elevenware.quickpki.IssuerInfo allows you to set the valid from and until of the issuer certificate, as well as a default 
duration of issued certificates. The default duration is 1 day. 

The class com.elevenware.quickpki.SubjectName allows you to set the subject name of the certificate, including the common name, organisation etc.

Both IssuerInfo and CertInfo can have a SubjectName added to them. Only CertInfo **must** have a SubjectName.

```java