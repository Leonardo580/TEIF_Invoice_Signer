# El Fatoora TEIF Invoice Signer (Java)

This project provides a Java implementation for signing Tunisian Electronic Invoice Format (TEIF) XML invoices according to the XAdES-BES standard specified by the `el fatoora` platform, using Apache Santuario. It also includes a basic HTTP server example to demonstrate receiving and signing an invoice via an API endpoint.

## Features

*   Signs TEIF XML invoices using XAdES-BES (Baseline Profile).
*   Complies with `el fatoora` specific requirements (IDs, Transforms, Policy Identifier).
*   Uses Apache Santuario for XML Digital Signature generation.
*   Includes required XAdES elements:
    *   `SigningTime`
    *   `SigningCertificateV2` (with `CertDigest` and `IssuerSerialV2`)
    *   `SignaturePolicyIdentifier` (with OID, Hash, and SPURI)
    *   `SignerRoleV2`
    *   `SignedDataObjectProperties`
*   Applies necessary transforms (Enveloped, XPath `not(ancestor-or-self::RefTtnVal)`, Exclusive C14N).
*   Handles XML "unpretty" preprocessing (compacting XML before signing).
*   Calculates and includes the required Signature Policy hash.
*   Includes a basic HTTP server example (`SimpleHttpServer.java` - *you'll need to add this*) to demonstrate signing via API.

## Prerequisites

*   **Java Development Kit (JDK):** Version 11 or higher recommended (check Santuario compatibility if using older versions).
*   **Maven or Gradle:** For managing dependencies and building the project.
*   **PKCS#12 Keystore:** A valid keystore (`.p12` file) containing your private key and the corresponding **CA-signed X.509 certificate** issued by an authority recognized by `el fatoora` (e.g., ANCE).
*   **Signature Policy Document:** The official `el fatoora` signature policy PDF file (`Politique_de_Signature_de_la_facture_2.0.pdf` or the current version).

## Setup and Configuration

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/Leonardo580/TEIF_Invoice_Signer.git
    cd TEIF_Invoice_Signer
    ```

2.  **Place Keystore:**
    *   Create a `keys/` directory in the project root (if it doesn't exist).
    *   Place your PKCS#12 keystore file (e.g., `keystore.p12`) inside the `keys/` directory.

3.  **Place Signature Policy PDF:**
    *   Place the downloaded `Politique_de_Signature_de_la_facture_2.0.pdf` (or the correct version) inside the `keys/` directory (or update the path in the code).

4.  **Configure `XadesSignerForTEIF.java`:**
    *   Open `.env`.
    *   Update the following constants with your specific details:
        ```dotenv
        KEYSTORE_TYPE="{YOUR_KEYSTORE_TYPE}" // example PKCS12
        KEYSTORE_PATH="PATH_TO_YOUR_KEY"  
        KEYSTORE_PASSWORD="{PASSWORD}"
        PRIVATE_KEY_ALIAS="{PIRVATE_KEY_ALIAS}"
        PRIVATE_KEY_PASSWORD="{PRIVATE_KEY_ALIAS}"
    
*   **Verify `PolicyHash` Implementation:** Ensure the `PolicyHash.CalculateSHA256Base64` method correctly calculates the SHA-256 hash of the PDF and encodes it in Base64.

5.  **Dependencies:**
    *   Ensure your `pom.xml` (for Maven) or `build.gradle` (for Gradle) includes the necessary dependencies:
        *   `org.apache.santuario:xmlsec` (e.g., version 3.0.3 or compatible)
        *   `org.bouncycastle:bcprov-jdk18on` (or appropriate version for your JDK)
        *   `org.slf4j:slf4j-api`
        *   A SLF4J implementation (e.g., `ch.qos.logback:logback-classic` or `org.slf4j:slf4j-simple`)
        *   (If using HTTP Server) `com.sun.net.httpserver:http` (usually part of JDK)

## Usage

### 1. Standalone Signing (Using `main` method)

This signs a predefined input XML file.

1.  **Configure:** Set the `INPUT_XML_PATH` and `OUTPUT_XML_PATH` constants in `XadesSignerForTEIF.java`.
2.  **Build:** Compile the project (e.g., `mvn clean package` or `gradle build`).
3.  **Run:** Execute the `XadesSignerForTEIF` class. The signed XML will be saved to the `OUTPUT_XML_PATH`.

### 2. Signing via HTTP API

This requires you to run a simple HTTP server class .


1.  **Run `APIEndpoint.java`:** Implement a basic HTTP server using `com.sun.net.httpserver.HttpServer`. Create an endpoint (`/sign-invoice`).
2.  **Endpoint Logic:**
    *   The endpoint accepts POST requests with the XML invoice content in the request body.
    *   Read the request body.
    *   Instantiate `XadesSignerForTEIF`.
    *   Write the signed XML string back as the HTTP response with `Content-Type: application/xml`.
3.  **Send Request:** Use a tool like `curl` or Postman to send a POST request to your server's endpoint (`http://localhost:10000/sign_invoice`) with the raw TEIF XML invoice in the request body.

**Example `curl` command:**

```bash
curl -X POST -H "Content-Type: application/xml" --data-binary "@path/to/your/invoice.xml" http://localhost:10000/sign-invoice -o signed_invoice_from_api.xml