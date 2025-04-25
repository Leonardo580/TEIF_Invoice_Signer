package org.example; // Your package name

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.Constants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.CanonicalizationMethod; // Standard API constants
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

import io.github.cdimascio.dotenv.Dotenv;

public class XadesSignerForTEIF {

    private static final Logger log = LoggerFactory.getLogger(XadesSignerForTEIF.class);
    private static final Dotenv dotenv = Dotenv.load();
    // --- Configuration ---
    private static final String KEYSTORE_TYPE = dotenv.get("KEYSTORE_TYPE");
    private static final String KEYSTORE_PATH = dotenv.get("KEYSTORE_PATH"); // CHANGE THIS
    private static final String KEYSTORE_PASSWORD = dotenv.get("KEYSTORE_PASSWORD"); // CHANGE THIS
    private static final String PRIVATE_KEY_ALIAS = dotenv.get("PRIVATE_KEY_ALIAS"); // CHANGE THIS
    private static final String PRIVATE_KEY_PASSWORD = dotenv.get("PRIVATE_KEY_PASSWORD"); // CHANGE THIS
    private static final String OUTPUT_XML_PATH_DIR = "elfatooraSpecTech/"; // CHANGE THIS (Corrected)

    // --- Signature Policy (Example - Verify if explicit policy needed) ---
    private static final boolean USE_EXPLICIT_POLICY = true; // Set to true for explicit policy
    private static final String POLICY_OID = "urn:oid:2.16.788.1.2.1";
    // ** IMPORTANT: You MUST pre-calculate the SHA-256 hash of your policy document if USE_EXPLICIT_POLICY=true **

    private static final String POLICY_DIGEST_VALUE_B64; // Example from doc

    static {
        try {
            POLICY_DIGEST_VALUE_B64 = PolicyHash.CalculateSHA256Base64("keys/politique_de_la_signature_de_la_facture_2.0.pdf");
        } catch (Exception e) {
            log.error("Could not calculate POLICY_DIGEST_VALUE_B64: ", e);
            throw new RuntimeException(e);
        }
    }

    private static final String POLICY_SPURI = "https://www.tradenet.com.tn/wp-content/uploads/simple-file-list/Politique_de_Signature_de_la_facture_2.0.pdf";

    // --- Signer Role ---
    private static final String SIGNER_ROLE = "Fournisseur"; // e.g., "supplier", "issuer"

    // --- Constants for XMLDSig/XAdES ---
    private static final String XMLDSIG_NS = Constants.SignatureSpecNS; // http://www.w3.org/2000/09/xmldsig#
    private static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#"; // XAdES v1.3.2 namespace
    private static final String XADES141_NS = "http://uri.etsi.org/01903/v1.4.1#"; // XAdES v1.4.1 namespace (for IssuerSerialV2)
    private static final String C14N_METHOD_ALG = CanonicalizationMethod.EXCLUSIVE; // http://www.w3.org/2001/10/xml-exc-c14n#
    private static final String DIGEST_METHOD_ALG = DigestMethod.SHA256; // http://www.w3.org/2001/04/xmlenc#sha256
    // Santuario often uses specific URIs for signature methods
    private static final String SIGNATURE_METHOD_ALG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final String XADES_SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties";

    // Document Reference ID (must match ObjectReference in DataObjectFormat)
    private static final String DOCUMENT_REFERENCE_ID = "r-id-frs"; // Example ID, ensure uniqueness if needed

    static {
        // Initialize Santuario and BouncyCastle Provider
        // XMLUtils.setIgnoreLineBreaks(true); // Optional: Can affect C14N if not careful
        org.apache.xml.security.Init.init();
        Security.addProvider(new BouncyCastleProvider());
        log.info("Santuario and BouncyCastle initialized.");
    }

    public static void main(String[] args) {
        try {
            log.info("Starting XML signing process...");
            XadesSignerForTEIF signer = new XadesSignerForTEIF();
            String xmlpath = "elfatooraSpecTech/Invoice Export Sample.xml";
            signer.signSave(xmlpath);
            log.info("XML signed successfully using Santuario! Output: {}", OUTPUT_XML_PATH_DIR);
        } catch (Exception e) {
            log.error("Error signing XML with Santuario: {}", e.getMessage(), e);
        }
    }

    public Document sign(String XmlPathOrText) throws Exception {
        // 1. Load Keystore
        log.debug("Loading keystore from: {}", KEYSTORE_PATH);
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        try (InputStream fis = new FileInputStream(KEYSTORE_PATH)) {
            ks.load(fis, KEYSTORE_PASSWORD.toCharArray());
        }
        PrivateKey privateKey = (PrivateKey) ks.getKey(PRIVATE_KEY_ALIAS, PRIVATE_KEY_PASSWORD.toCharArray());
        X509Certificate signingCert = (X509Certificate) ks.getCertificate(PRIVATE_KEY_ALIAS);
        if (privateKey == null || signingCert == null) {
            throw new KeyStoreException("Could not retrieve key or certificate for alias: " + PRIVATE_KEY_ALIAS);
        }
        log.debug("Keystore loaded successfully. Certificate Subject: {}", signingCert.getSubjectX500Principal());

        // 2. Load XML Document
        log.debug("Loading XML document from: {}", XmlPathOrText);
        Document doc = loadDocument(XmlPathOrText);
        Element rootElement = doc.getDocumentElement();
        log.debug("XML document loaded.");

        // 3. Prepare XMLSignature Object
        String signatureId = "SigFrs";// ID for the Signature element itself
        String signedPropsId = "xades-SigFrs"; // ID for SignedProperties

        XMLSignature sig = new XMLSignature(doc, "" /* Base URI */, SIGNATURE_METHOD_ALG, C14N_METHOD_ALG);
        sig.setId(signatureId); // Set ID on the Signature element

        // Append the signature element to the root element (enveloped)
        rootElement.appendChild(sig.getElement());
        // Ensure XAdES namespace is declared on the Signature element or an ancestor
        sig.getElement().setAttributeNS(Constants.NamespaceSpecNS, "xmlns:xades", XADES_NS);
        sig.getElement().setAttributeNS(Constants.NamespaceSpecNS, "xmlns:xades141", XADES141_NS); // For IssuerSerialV2 if using v1.4.1

        // 4. Create Transforms for Document Reference
        log.debug("Creating transforms for document reference.");
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        XPathContainer xpathC_RefTtnVal = new XPathContainer(doc);
        xpathC_RefTtnVal.setXPath("not(ancestor-or-self::RefTtnVal)");
        Element xpathElement_RefTtnVal = xpathC_RefTtnVal.getElement();
        // Optional: Add XPath Transform if needed (e.g., to exclude validation refs)
        // XPathContainer xpathC = new XPathContainer(doc);
        // xpathC.setXPath("not(ancestor-or-self::*[local-name()='ValidationRef'])"); // Example XPath
        // transforms.addTransform(Transforms.TRANSFORM_XPATH, xpathC.getElementPlusReturns());
        transforms.addTransform(Transforms.TRANSFORM_XPATH, xpathElement_RefTtnVal);
        transforms.addTransform(C14N_METHOD_ALG); // Add Exclusive C14N

        // 5. Add Document Reference (Reference to the XML being signed)
        log.debug("Adding reference to the document (URI='').");
        sig.addDocument(
                "" /* URI="" means the whole document */,
                transforms,
                DIGEST_METHOD_ALG,
                DOCUMENT_REFERENCE_ID, // Assign an ID to this reference
                null /* Type attribute (optional for data ref) */
        );

        // 6. Create XAdES Qualifying Properties structure
        log.debug("Creating XAdES QualifyingProperties structure.");
        Element xadesQualifyingProperties = createXAdESProperties(doc, signingCert, signatureId, signedPropsId);

        // 7. Create a ds:Object container and add the XAdES properties to it
        log.debug("Creating ds:Object container for XAdES properties.");
        ObjectContainer objectContainer = new ObjectContainer(doc);
        // Add the <xades:QualifyingProperties> element INSIDE the <ds:Object>
        objectContainer.getElement().appendChild(xadesQualifyingProperties);
        // Append the <ds:Object> (containing XAdES properties) to the <ds:Signature>
        sig.appendObject(objectContainer);
        log.debug("ds:Object containing XAdES properties added to signature.");

        // 8. Add Reference to SignedProperties
        log.debug("Adding reference to SignedProperties (URI='{}').", "#" + signedPropsId);
        Transforms signedPropsTransforms = new Transforms(doc);
        // Reference to SignedProperties MUST be canonicalized before digesting
        signedPropsTransforms.addTransform(C14N_METHOD_ALG);

        sig.addDocument(
                "#" + signedPropsId,        // URI points to the ID of SignedProperties
                signedPropsTransforms,      // Apply C14N transform
                DIGEST_METHOD_ALG,          // Digest algorithm
                null,                       // Reference ID (optional here)
                XADES_SIGNED_PROPERTIES_TYPE // TYPE attribute is crucial
        );

        // 9. Add KeyInfo
        log.debug("Adding KeyInfo (certificate).");
        sig.addKeyInfo(signingCert);
        // If you need KeyName or other elements, add them via sig.getKeyInfo().add(...)

        // 10. Sign
        log.info("Performing signature calculation...");
        sig.sign(privateKey);
        log.info("Signature calculation complete.");
        // 11. Save Output
        return doc;
    }

    /**
     * This function sign xml files then save it
     *
     * @param XmlPathOrText
     * @throws Exception
     */
    public void signSave(String XmlPathOrText) throws Exception {
        log.info("Saving signed document to: {}", OUTPUT_XML_PATH_DIR);

        Document doc = sign(XmlPathOrText);
        String file_name = getFileName(XmlPathOrText);
        saveDocument(doc, OUTPUT_XML_PATH_DIR + String.format("%s_signed.xml", file_name));

    }
    public String signAndGetText(String XmlPathOrText) throws Exception{
        Document doc = sign(XmlPathOrText);
        return getDocumentText(doc);
    }

    private String getFileName(String path) {
        assert path != null;
        if (path.isEmpty())
            return "";
        char c = '\0';
        int extension_point = path.lastIndexOf('.');
        int slash = path.lastIndexOf('/');
        return path.substring(slash, extension_point);
    }

    private Element createXAdESProperties(Document doc, X509Certificate cert, String signatureId, String signedPropsId)
            throws XMLSecurityException, CertificateEncodingException, NoSuchAlgorithmException {

        log.debug("Building <xades:QualifyingProperties Target='{}'>", "#SigFrs");

        // Create root <xades:QualifyingProperties>
        Element qualifyingProps = doc.createElementNS(XADES_NS, "xades:QualifyingProperties");
        qualifyingProps.setAttribute("Target", "#SigFrs"); // MUST point to the <ds:Signature> ID

        // Create <xades:SignedProperties>
        Element signedProps = doc.createElementNS(XADES_NS, "xades:SignedProperties");
        signedProps.setAttribute("Id", "xades-SigFrs"); // Set ID for the reference
        // *** CRUCIAL: Register this attribute as an ID type with the DOM ***
        signedProps.setIdAttribute("Id", true);
        qualifyingProps.appendChild(signedProps);
        log.debug("Added <xades:SignedProperties Id='{}'>", signedPropsId);

        // Create <xades:SignedSignatureProperties>
        Element signedSigProps = doc.createElementNS(XADES_NS, "xades:SignedSignatureProperties");
        signedProps.appendChild(signedSigProps);

        // --- Signing Time ---
        Element signingTime = doc.createElementNS(XADES_NS, "xades:SigningTime");
        // Use ISO 8601 format, Z denotes UTC
        String formattedTime = DateTimeFormatter.ISO_INSTANT.format(Instant.now().atOffset(ZoneOffset.UTC));
        signingTime.setTextContent(formattedTime);
        signedSigProps.appendChild(signingTime);
        log.debug("Added SigningTime: {}", formattedTime);

        // --- Signing Certificate V2 ---
        Element signingCertV2 = doc.createElementNS(XADES_NS, "xades:SigningCertificateV2");
        signedSigProps.appendChild(signingCertV2);
        Element certV2 = doc.createElementNS(XADES_NS, "xades:Cert");
        signingCertV2.appendChild(certV2);
        Element certDigest = doc.createElementNS(XADES_NS, "xades:CertDigest");
        certV2.appendChild(certDigest);
        Element digestMethod = doc.createElementNS(XMLDSIG_NS, "ds:DigestMethod");
        digestMethod.setAttribute("Algorithm", DigestMethod.SHA256); // Use SHA-256 for cert digest
        certDigest.appendChild(digestMethod);
        Element digestValue = doc.createElementNS(XMLDSIG_NS, "ds:DigestValue");
        String certDigestBase64 = calculateCertDigestBase64(cert, "SHA-256");
        digestValue.setTextContent(certDigestBase64);
        certDigest.appendChild(digestValue);

        // --- Issuer Serial V2 (Using XAdES v1.4.1 namespace for clarity if needed) ---
        // Structure according to XAdES / XMLDSig v2 recommendations often nests under Cert/CertDigest
        Element issuerSerialV2 = doc.createElementNS(XADES141_NS, "xades141:IssuerSerialV2"); // Or XADES_NS if schema allows
        // Option 1: Place next to CertDigest (Common in some profiles)
        // certV2.appendChild(issuerSerialV2);
        // Option 2: Place directly under SigningCertificateV2 (also seen)
        signingCertV2.appendChild(issuerSerialV2);

        // According to ds:X509Data structure, we include X509IssuerSerial
        Element x509IssuerSerial = doc.createElementNS(XMLDSIG_NS, "ds:X509IssuerSerial");
        issuerSerialV2.appendChild(x509IssuerSerial); // Place inside IssuerSerialV2

        Element x509IssuerName = doc.createElementNS(XMLDSIG_NS, "ds:X509IssuerName");
        x509IssuerName.setTextContent(cert.getIssuerX500Principal().getName()); // RFC2253 format is common
        x509IssuerSerial.appendChild(x509IssuerName);

        Element x509SerialNumber = doc.createElementNS(XMLDSIG_NS, "ds:X509SerialNumber");
        x509SerialNumber.setTextContent(cert.getSerialNumber().toString());
        x509IssuerSerial.appendChild(x509SerialNumber);
        log.debug("Added SigningCertificateV2 with Issuer: {}, Serial: {}, Digest: {}",
                x509IssuerName.getTextContent(), x509SerialNumber.getTextContent(), certDigestBase64);


        // --- Signature Policy Identifier ---
        Element sigPolicyId = doc.createElementNS(XADES_NS, "xades:SignaturePolicyIdentifier");
        signedSigProps.appendChild(sigPolicyId);

        if (USE_EXPLICIT_POLICY) {
            log.debug("Adding Explicit Signature Policy Identifier (OID: {}).", POLICY_OID);
            Element sigPolicyId_Inner = doc.createElementNS(XADES_NS, "xades:SignaturePolicyId");
            sigPolicyId.appendChild(sigPolicyId_Inner);

            Element sigPolId = doc.createElementNS(XADES_NS, "xades:SigPolicyId");
            sigPolicyId_Inner.appendChild(sigPolId);
            Element identifier = doc.createElementNS(XADES_NS, "xades:Identifier");
            identifier.setTextContent(POLICY_OID);
            // identifier.setAttribute("Qualifier", "OIDAsURN"); // Optional qualifier
            sigPolId.appendChild(identifier);
            // Element description = doc.createElementNS(XADES_NS, "xades:Description"); // Optional
            // description.setTextContent("Policy Description");
            // sigPolId.appendChild(description);

            Element sigPolHash = doc.createElementNS(XADES_NS, "xades:SigPolicyHash");
            sigPolicyId_Inner.appendChild(sigPolHash);
            Element polDigestMethod = doc.createElementNS(XMLDSIG_NS, "ds:DigestMethod");
            polDigestMethod.setAttribute("Algorithm", DigestMethod.SHA256);
            sigPolHash.appendChild(polDigestMethod);
            Element polDigestValue = doc.createElementNS(XMLDSIG_NS, "ds:DigestValue");
            polDigestValue.setTextContent(POLICY_DIGEST_VALUE_B64); // Use pre-calculated hash
            sigPolHash.appendChild(polDigestValue);

            if (POLICY_SPURI != null && !POLICY_SPURI.trim().isEmpty()) {
                Element sigPolQualifiers = doc.createElementNS(XADES_NS, "xades:SigPolicyQualifiers");
                sigPolicyId_Inner.appendChild(sigPolQualifiers);
                Element sigPolQualifier = doc.createElementNS(XADES_NS, "xades:SigPolicyQualifier");
                sigPolQualifiers.appendChild(sigPolQualifier);
                Element spUri = doc.createElementNS(XADES_NS, "xades:SPURI");
                spUri.setTextContent(POLICY_SPURI);
                sigPolQualifier.appendChild(spUri);
            }
        } else {
            // --- Use Implied Policy (Common for XAdES-BES) ---
            log.debug("Adding Implied Signature Policy Identifier.");
            Element sigPolicyImplied = doc.createElementNS(XADES_NS, "xades:SignaturePolicyImplied");
            sigPolicyId.appendChild(sigPolicyImplied);
        }


        // --- Signer Role V2 ---
        if (SIGNER_ROLE != null && !SIGNER_ROLE.trim().isEmpty()) {
            log.debug("Adding SignerRoleV2: {}", SIGNER_ROLE);
            Element signerRoleV2 = doc.createElementNS(XADES_NS, "xades:SignerRoleV2");
            signedSigProps.appendChild(signerRoleV2);
            Element claimedRoles = doc.createElementNS(XADES_NS, "xades:ClaimedRoles");
            signerRoleV2.appendChild(claimedRoles);
            Element claimedRole = doc.createElementNS(XADES_NS, "xades:ClaimedRole");
            // Role might need specific encoding or structure based on profile (e.g., an OID, URI, or text)
            claimedRole.setTextContent(SIGNER_ROLE);
            claimedRoles.appendChild(claimedRole);
            // Can add <CertifiedRoles> if using attribute certificates
        }

        // --- Signed Data Object Properties ---
        log.debug("Adding SignedDataObjectProperties for Reference ID: {}", DOCUMENT_REFERENCE_ID);
        Element signedDataObjProps = doc.createElementNS(XADES_NS, "xades:SignedDataObjectProperties");
        signedProps.appendChild(signedDataObjProps);
        Element dataObjFormat = doc.createElementNS(XADES_NS, "xades:DataObjectFormat");
        // Reference the document reference using its ID
        dataObjFormat.setAttribute("ObjectReference", "#" + DOCUMENT_REFERENCE_ID);
        signedDataObjProps.appendChild(dataObjFormat);

        Element mimeType = doc.createElementNS(XADES_NS, "xades:MimeType");
        //mimeType.setTextContent("application/xml"); // Or application/octet-stream if appropriate
        mimeType.setTextContent("application/octet-stream");
        dataObjFormat.appendChild(mimeType);
        // Optionally add Encoding, Identifier if needed:
        // Element encoding = doc.createElementNS(XADES_NS, "xades:Encoding");
        // encoding.setTextContent("UTF-8"); // Example
        // dataObjFormat.appendChild(encoding);

        log.debug("Finished building XAdES properties structure.");
        return qualifyingProps; // Return the top-level element
    }

    private String calculateCertDigestBase64(X509Certificate cert, String digestAlg)
            throws CertificateEncodingException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(digestAlg); // e.g., "SHA-256"
        byte[] digest = md.digest(cert.getEncoded());
        return Base64.getEncoder().encodeToString(digest);
    }

    // --- XML Helper Methods ---
    private Document loadDocument(String xmlPath) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true); // Crucial!
        // Optional: Add security features to prevent XXE
        dbf.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        // dbf.setXIncludeAware(false); // Disable XInclude if not needed
        // dbf.setExpandEntityReferences(false); // Don't expand external entities

        DocumentBuilder db = dbf.newDocumentBuilder();
        // Optional: Set an ErrorHandler to catch parsing errors
        // db.setErrorHandler(...);
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty("omit-xml-declaration", "yes");
        transformer.setOutputProperty("indent", "no"); // Crucial for single line
        transformer.setOutputProperty("standalone", "yes"); // Optional
        StringWriter writer = new StringWriter();
        File xml = new File(xmlPath);
        if (xml.exists() && !xml.isDirectory())
            transformer.transform(new DOMSource(db.parse(new File(xmlPath))), new StreamResult(writer));
        else
            transformer.transform(new DOMSource(db.parse(xml)), new StreamResult(writer));
        return db.parse(new InputSource(new StringReader(writer.toString())));
    }

    private void saveDocument(Document doc, String outputPath) throws Exception {
        Transformer transformer = extract_xml();
        try (OutputStream out = new FileOutputStream(outputPath)) {
            transformer.transform(new DOMSource(doc), new StreamResult(out));
        }
    }

    private String getDocumentText(Document doc) throws TransformerException {
        StringWriter writer = new StringWriter(0);

        Transformer transformer = extract_xml();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));
        return writer.toString();

    }

    private Transformer extract_xml() throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        // Optional: Add security features
        try {
            tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        } catch (IllegalArgumentException e) {
            log.warn("TransformerFactory does not support setting ACCESS_EXTERNAL_DTD/STYLESHEET attributes.");
        }

        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        // Optional: Pretty print for readability - Note: Whitespace changes can break signatures if not careful!
        // Use only for debugging if needed, C14N handles canonical form.
        // transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        // transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        return transformer;

    }
}