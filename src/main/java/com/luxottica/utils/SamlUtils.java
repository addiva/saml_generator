package com.luxottica.utils;
import com.luxottica.models.Claims;
import org.joda.time.DateTime;
import org.joda.time.LocalDateTime;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.*;
import org.opensaml.saml.common.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;


import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import static com.luxottica.global.GlobalProperties.*;
import static com.luxottica.utils.PrivateKeyUtils.*;

public class SamlUtils {

    public static String generate(Claims claims) throws Exception {
        // Initialize OpenSAML
        InitializationService.initialize();
        // Create a new Response
        Response response = new ResponseBuilder().buildObject();

        // Set the ID, version, and issue instant
        response.setDestination(destination);
        response.setID("_" + generateRandomIdentifier());
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssueInstant(DateTime.now());

        // Create an Issuer
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(entityID);
        response.setIssuer(issuer);

        Status status = new StatusBuilder().buildObject();
        StatusCode statusCode = new StatusCodeBuilder().buildObject();
        statusCode.setValue(StatusCode.SUCCESS);
        status.setStatusCode(statusCode);
        response.setStatus(status);

        // Create an Assertion
        Assertion assertion = new AssertionBuilder().buildObject();
        assertion.setID("_" + generateRandomIdentifier());
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssueInstant(DateTime.now());

        // Set Issuer for Assertion
        Issuer assertionIssuer = new IssuerBuilder().buildObject();
        assertionIssuer.setValue(entityID);
        assertion.setIssuer(assertionIssuer);

        // Create Subject for Assertion
        Subject subject = new SubjectBuilder().buildObject();
        NameID nameID = new NameIDBuilder().buildObject();
        nameID.setFormat(NameID.UNSPECIFIED);
        nameID.setValue(claims.getUserID());
        subject.setNameID(nameID);

        // Create SubjectConfirmation
        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

        SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationDataBuilder().buildObject();
        subjectConfirmationData.setNotOnOrAfter(new LocalDateTime().now().plusMinutes(10).toDateTime());
        subjectConfirmationData.setRecipient(destination);

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);

        assertion.setSubject(subject);

        // Create Conditions for Assertion
        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotBefore(new LocalDateTime().now().minusMinutes(5).toDateTime());
        conditions.setNotOnOrAfter(new LocalDateTime().now().plusMinutes(10).toDateTime());

        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
        Audience audienceObj = new AudienceBuilder().buildObject();
        audienceObj.setAudienceURI(audience);
        audienceRestriction.getAudiences().add(audienceObj);

        conditions.getAudienceRestrictions().add(audienceRestriction);
        assertion.setConditions(conditions);

        // Create AuthnStatement
        AuthnStatement authnStatement = new AuthnStatementBuilder().buildObject();
        authnStatement.setAuthnInstant(new DateTime());
        authnStatement.setSessionIndex("_" + generateRandomIdentifier());

        AuthnContext authnContext = new AuthnContextBuilder().buildObject();
        AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
        authnContextClassRef.setAuthnContextClassRef("UNSPECIFIED");
        authnContext.setAuthnContextClassRef(authnContextClassRef);

        authnStatement.setAuthnContext(authnContext);
        assertion.getAuthnStatements().add(authnStatement);

        // Create Attribute Statement
        AttributeStatement attributeStatement = new AttributeStatementBuilder().buildObject();

        // Add attributes to Attribute Statement
        if(claims.getName()!=null&&!claims.getName().isEmpty())
            addAttribute(attributeStatement, "name", claims.getName());
        if(claims.getSurname()!=null&&!claims.getSurname().isEmpty())
            addAttribute(attributeStatement, "surname", claims.getSurname());
        if(claims.getEmail()!=null&&!claims.getEmail().isEmpty())
            addAttribute(attributeStatement, "email", claims.getEmail());
        if(claims.getCompanyCode()!=null&&!claims.getCompanyCode().isEmpty())
            addAttribute(attributeStatement, "companyCode", claims.getCompanyCode());
        if(claims.getContry()!=null&&!claims.getContry().isEmpty())
            addAttribute(attributeStatement, "country", claims.getContry());

        // Add Attribute Statement to Assertion
        assertion.getAttributeStatements().add(attributeStatement);

        // Sign the Assertion
        assertion = signAssertion(assertion, privateKeyStr, certificateStr);

        // Sign the Response
        //response = signResponse(response, privateKeyStr, certificateStr);

        // Add the Assertion
        response.getAssertions().add(assertion);

        // Convert Response to XML String
        String responseXml = marshallResponse(response);

        return responseXml;
    }
    private static final int DEFAULT_IDENTIFIER_LENGTH = 16;
    public static String generateRandomIdentifier() {
        return generateRandomIdentifier(DEFAULT_IDENTIFIER_LENGTH);
    }
    //Used to give a random id to the saml
    public static String generateRandomIdentifier(int length) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return new BigInteger(1, bytes).toString(16);
    }
    public static String marshallResponse(Response response) throws MarshallingException, TransformerException {
        // Create a Document to hold the marshalled Response
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder;
        try {
            documentBuilder = documentBuilderFactory.newDocumentBuilder();
        } catch (Exception e) {
            throw new MarshallingException("Error creating DocumentBuilder", e);
        }
        Document document = documentBuilder.newDocument();

        // Get the marshaller for Response
        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response);

        // Marshall the Response into the Document
        Element element = marshaller.marshall(response, document);

        // Convert the DOM element to a string
        return elementToString(element);
    }

    public static String elementToString(Element element) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(element), new StreamResult(writer));
        return writer.getBuffer().toString();
    }
    //Adds the claim if there is a value for them to avoid useless null's
    private static void addAttribute(AttributeStatement attributeStatement, String name, String value) {
        if (value != null && !value.isEmpty()) {
            Attribute attribute = new AttributeBuilder().buildObject();
            attribute.setName(name);
            XSStringBuilder stringBuilder = new XSStringBuilder();
            XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
            stringValue.setValue(value);
            attribute.getAttributeValues().add(stringValue);
            attributeStatement.getAttributes().add(attribute);
        }
    }
    //if the signature is located in the assertion
    private static Assertion signAssertion(Assertion assertion, String privateKeyStr, String certificateStr) throws Exception {
        // Parse the private key string
        PrivateKey privateKey = parsePrivateKey(privateKeyStr);

        // Parse the certificate string
        X509Certificate certificate = parseCertificate(certificateStr);

        // Create X509Credential
        BasicX509Credential credential = new BasicX509Credential(certificate, privateKey);

        // Generate KeyInfo
        KeyInfo keyInfo = generateKeyInfo(credential, certificate);

        // Create a Signature
        Signature signature = (Signature) XMLObjectProviderRegistrySupport
                .getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(credential);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setKeyInfo(keyInfo);
        assertion.setSignature(signature);

        ((SAMLObjectContentReference)signature.getContentReferences().get(0))
                .setDigestAlgorithm(EncryptionConstants.ALGO_ID_DIGEST_SHA256);

        // Marshall and Sign
        Marshaller marshaller = XMLObjectProviderRegistrySupport
                .getMarshallerFactory()
                .getMarshaller(assertion);
        marshaller.marshall(assertion);

        Signer.signObject(signature);

        return assertion;
    }
    //if the signature is located in the response
    private static Response signResponse(Response response, String privateKeyStr, String certificateStr) throws Exception {
        // Parse the private key string
        PrivateKey privateKey = parsePrivateKey(privateKeyStr);

        // Parse the certificate string
        X509Certificate certificate = parseCertificate(certificateStr);

        // Create X509Credential
        BasicX509Credential credential = new BasicX509Credential(certificate, privateKey);

        // Generate KeyInfo
        KeyInfo keyInfo = generateKeyInfo(credential, certificate);

        // Create a Signature
        Signature signature = (Signature) XMLObjectProviderRegistrySupport
                .getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(credential);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setKeyInfo(keyInfo);

        response.setSignature(signature);

        // Marshall and Sign
        Marshaller marshaller = XMLObjectProviderRegistrySupport
                .getMarshallerFactory()
                .getMarshaller(response);
        marshaller.marshall(response);

        Signer.signObject(signature);

        return response;
    }
}