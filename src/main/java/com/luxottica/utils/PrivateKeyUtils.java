package com.luxottica.utils;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Data;

import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class PrivateKeyUtils {
    //parses the String of a private key to an PrivateKey obj
    public static PrivateKey parsePrivateKey(String privateKeyStr) throws Exception {
        PEMParser pemParser = new PEMParser(new StringReader(privateKeyStr));
        Object obj = pemParser.readObject();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

        if (obj instanceof PEMKeyPair) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) obj;
            KeyPair keyPair = converter.getKeyPair(pemKeyPair);
            return keyPair.getPrivate();
        } else if (obj instanceof PrivateKeyInfo) {
            PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) obj;
            return converter.getPrivateKey(privateKeyInfo);
        } else {
            throw new IllegalArgumentException("Unsupported PEM object: " + obj.getClass().getName());
        }
    }
    //parses the String of a certificate to an X509Certificate obj
    public static X509Certificate parseCertificate(String certificateStr) throws Exception {
        String cleanCert = certificateStr.replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
        byte[] certBytes = Base64.getDecoder().decode(cleanCert);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(new java.io.ByteArrayInputStream(certBytes));
    }
    //Extracts the key info, so you can sign the samlResponse
    public static KeyInfo generateKeyInfo(BasicX509Credential credential, X509Certificate certificate) {
        //will explode if OpenSAML isn't inizialized
        KeyInfo keyInfo = (KeyInfo) XMLObjectProviderRegistrySupport
                .getBuilderFactory()
                .getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME)
                .buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
        X509Data x509Data = (X509Data) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(X509Data.DEFAULT_ELEMENT_NAME)
                .buildObject(X509Data.DEFAULT_ELEMENT_NAME);
        org.opensaml.xmlsec.signature.X509Certificate xmlCertificate = (org.opensaml.xmlsec.signature.X509Certificate)
                XMLObjectProviderRegistrySupport.getBuilderFactory()
                        .getBuilder(org.opensaml.xmlsec.signature.X509Certificate.DEFAULT_ELEMENT_NAME)
                        .buildObject(org.opensaml.xmlsec.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
        try {
            xmlCertificate.setValue(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }

        x509Data.getX509Certificates().add(xmlCertificate);
        keyInfo.getX509Datas().add(x509Data);

        if (keyInfo == null) {
            System.err.println("KeyInfo generation returned null.");
        }

        return keyInfo;
    }
}
