package com.luxottica.utils;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.metadata.*;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.w3c.dom.Element;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static com.luxottica.global.GlobalProperties.*;
import static com.luxottica.utils.PrivateKeyUtils.*;

public class MetadataUtils {
    public static String generator() throws Exception {
        // Initialize OpenSAML
        InitializationService.initialize();

        // Initialize the XMLObjectBuilderFactory
        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        // Create EntityDescriptor
        EntityDescriptor entityDescriptor = (EntityDescriptor) builderFactory
                .getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME)
                .buildObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        entityDescriptor.setEntityID(entityID);

        // Create IDPSSODescriptor
        IDPSSODescriptor idpSSODescriptor = (IDPSSODescriptor) builderFactory
                .getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME)
                .buildObject(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

        // Parse the private key string
        PrivateKey privateKey = parsePrivateKey(privateKeyStr);

        // Parse the certificate string
        X509Certificate certificate = parseCertificate(certificateStr);

        // Create X509Credential
        BasicX509Credential credential = new BasicX509Credential(certificate, privateKey);

        // Generate KeyInfo element
        KeyInfo keyInfo = generateKeyInfo(credential, certificate);

        // Create KeyDescriptor
        KeyDescriptor keyDescriptor = (KeyDescriptor) XMLObjectProviderRegistrySupport
                .getBuilderFactory()
                .getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME)
                .buildObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        keyDescriptor.setUse(UsageType.SIGNING);
        keyDescriptor.setKeyInfo(keyInfo);

        // Add KeyDescriptor to IDPSSODescriptor
        idpSSODescriptor.getKeyDescriptors().add(keyDescriptor);

        // Create SingleLogoutService with bindings
        SingleLogoutService sloRedirect = (SingleLogoutService) builderFactory
                .getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME)
                .buildObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);
        sloRedirect.setLocation(sloLocation);
        sloRedirect.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");

        SingleLogoutService sloPost = (SingleLogoutService) builderFactory
                .getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME)
                .buildObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);
        sloPost.setLocation(sloLocation);
        sloPost.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

        idpSSODescriptor.getSingleLogoutServices().add(sloRedirect);
        idpSSODescriptor.getSingleLogoutServices().add(sloPost);

        // Create SingleSignOnService with bindings
        SingleSignOnService ssoRedirect = (SingleSignOnService) builderFactory
                .getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME)
                .buildObject(SingleSignOnService.DEFAULT_ELEMENT_NAME);
        ssoRedirect.setLocation(ssoLocation);
        ssoRedirect.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");

        SingleSignOnService ssoPost = (SingleSignOnService) builderFactory
                .getBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME)
                .buildObject(SingleSignOnService.DEFAULT_ELEMENT_NAME);
        ssoPost.setLocation(ssoLocation);
        ssoPost.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

        idpSSODescriptor.getSingleSignOnServices().add(ssoRedirect);
        idpSSODescriptor.getSingleSignOnServices().add(ssoPost);

        // Set protocol support
        idpSSODescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        // Create NameIDFormat
        NameIDFormat nameIDFormat = (NameIDFormat) builderFactory
                .getBuilder(NameIDFormat.DEFAULT_ELEMENT_NAME)
                .buildObject(NameIDFormat.DEFAULT_ELEMENT_NAME);
        nameIDFormat.setFormat(NameIDType.TRANSIENT);
        idpSSODescriptor.getNameIDFormats().add(nameIDFormat);

        // Add IDPSSODescriptor to EntityDescriptor
        entityDescriptor.getRoleDescriptors().add(idpSSODescriptor);

        entityDescriptor.getRoleDescriptors().add(idpSSODescriptor);
        // Convert KeyInfo to XML
        Marshaller marshaller = XMLObjectProviderRegistrySupport
                .getMarshallerFactory()
                .getMarshaller(entityDescriptor);
        Element metadataElement = marshaller
                .marshall(entityDescriptor);
        String metadataXML = SerializeSupport
                .nodeToString(metadataElement);
        return metadataXML;
    }
}
