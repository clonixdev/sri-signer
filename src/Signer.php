<?php

namespace DazzaDev\SriSigner;

use DateTime;
use DateTimeZone;
use DazzaDev\SriSigner\Exceptions\CertificateException;
use DazzaDev\SriSigner\Exceptions\SignerException;
use DOMDocument;
use DOMElement;
use Ramsey\Uuid\Uuid;

class Signer
{
    /**
     * XML string
     */
    private string $xmlString = '';

    /**
     * DOMDocument
     */
    private DOMDocument $domDocument;

    /**
     * Version
     */
    private string $version = '1.0';

    /**
     * Encoding
     */
    private string $encoding = 'UTF-8';

    /**
     * Random numbers
     */
    private array $randomNumbers = [];

    /**
     * Hash of comprobante element
     */
    private string $hashComprobante = '';

    /**
     * Hash of signed properties element
     */
    private string $hashSignedProperties = '';

    /**
     * Namespace declarations for canonicalization
     */
    private array $ns = [
        'xmlns:ds' => 'http://www.w3.org/2000/09/xmldsig#',
        'xmlns:xades' => 'http://uri.etsi.org/01903/v1.3.2#',
    ];

    /**
     * Hash of key info element
     */
    private string $hashKeyInfo = '';

    /**
     * Signing time
     */
    private string $signingTime = '';

    /**
     * Signed XML string
     */
    private string $xmlSigned = '';

    /**
     * Signature element
     */
    private ?DOMElement $signatureElement = null;

    /**
     * Key info element
     */
    private ?DOMElement $keyInfoElement = null;

    /**
     * Signed properties element
     */
    private ?DOMElement $signedPropertiesElement = null;

    /**
     * Signed info element
     */
    private ?DOMElement $signedInfoElement = null;

    /**
     * Signature value element
     */
    private ?DOMElement $signatureValueElement = null;

    /**
     * Object element
     */
    private ?DOMElement $objectElement = null;

    /**
     * Certificate
     */
    protected Certificate $certificate;

    /**
     * Constructor
     */
    public function __construct(string $certificatePath, string $certificatePassword)
    {
        $this->certificate = new Certificate($certificatePath, $certificatePassword);
    }

    /**
     * Load XML into DOMDocument
     */
    public function loadXML(DOMDocument|string $xml): Signer
    {
        if ($xml instanceof DOMDocument) {
            $this->xmlString = $xml->saveXML();
        } elseif (is_string($xml)) {
            $this->xmlString = $xml;
        } else {
            throw new SignerException('Invalid XML input.');
        }

        $this->domDocument = new DOMDocument($this->version, $this->encoding);
        $this->domDocument->preserveWhiteSpace = false;
        $this->domDocument->formatOutput = false;
        $this->domDocument->loadXML($this->xmlString);

        return $this;
    }

    /**
     * Sign the XML document with XAdES-BES format
     */
    public function sign(): string
    {
        // Get hash of comprobante element BEFORE generating dynamic elements
        $this->hashComprobante = $this->getHashComprobante();

        // Set signing time
        $this->signingTime = $this->getSigningTime();

        // Generate the 8 random numbers required for XAdES structure
        $this->generateRandomNumbers();

        // Create signature structure and add it to the document temporarily
        $this->createSignatureStructure();

        $this->domDocument->documentElement->appendChild($this->signatureElement);

        // Get the formatted XML with proper indentation but remove signature indentation
        $this->xmlSigned = $this->domDocument->saveXML();

        return $this->xmlSigned;
    }

    /**
     * Create the complete signature structure
     */
    private function createSignatureStructure(): DOMElement
    {
        $this->signatureElement = $this->domDocument->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:Signature');
        $this->signatureElement->setAttribute('Id', 'Signature-'.$this->randomNumbers['signature']);
        $this->signatureElement->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', 'http://www.w3.org/2000/09/xmldsig#');

        // Create KeyInfo
        $this->createKeyInfo();

        // Create SignedProperties using the separate method
        $this->createSignedProperties();

        // Create SignedInfo
        $this->createSignedInfo();

        // Create SignatureValue
        $this->createSignatureValue();

        // Create Object with XAdES properties
        $this->createObject();

        // Insert SignatureValue before KeyInfo
        $this->signatureElement->appendChild($this->signedInfoElement);
        $this->signatureElement->appendChild($this->signatureValueElement);
        $this->signatureElement->appendChild($this->keyInfoElement);
        $this->signatureElement->appendChild($this->objectElement);

        return $this->signatureElement;
    }

    /**
     * Create the Object element with XAdES properties
     */
    private function createObject(): DOMElement
    {
        $this->objectElement = $this->domDocument->createElement('ds:Object');
        $this->objectElement->setAttribute('Id', 'SignatureObject-'.$this->randomNumbers['object']);

        $qualifyingProperties = $this->domDocument->createElement('xades:QualifyingProperties');
        $qualifyingProperties->setAttribute('xmlns:xades', 'http://uri.etsi.org/01903/v1.3.2#');
        $qualifyingProperties->setAttribute('Target', '#Signature-'.$this->randomNumbers['signature']);

        $qualifyingProperties->appendChild($this->signedPropertiesElement);
        $this->objectElement->appendChild($qualifyingProperties);

        return $this->objectElement;
    }

    /**
     * Create the KeyInfo element
     */
    private function createKeyInfo(): DOMElement
    {
        $this->keyInfoElement = $this->domDocument->createElement('ds:KeyInfo');
        $this->keyInfoElement->setAttribute('Id', 'Certificate-'.$this->randomNumbers['certificate']);

        // X509Data
        $x509Data = $this->domDocument->createElement('ds:X509Data');
        $x509Certificate = $this->domDocument->createElement('ds:X509Certificate');

        // Get certificate content
        $x509Certificate->nodeValue = $this->certificate->getCertificateContent();
        $x509Data->appendChild($x509Certificate);
        $this->keyInfoElement->appendChild($x509Data);

        // KeyValue
        $keyValue = $this->domDocument->createElement('ds:KeyValue');
        $rsaKeyValue = $this->domDocument->createElement('ds:RSAKeyValue');

        $modulus = $this->domDocument->createElement('ds:Modulus');
        $modulus->nodeValue = base64_encode($this->certificate->getModulus());
        $rsaKeyValue->appendChild($modulus);

        $exponent = $this->domDocument->createElement('ds:Exponent');
        $exponent->nodeValue = base64_encode($this->certificate->getExponent());
        $rsaKeyValue->appendChild($exponent);

        $keyValue->appendChild($rsaKeyValue);
        $this->keyInfoElement->appendChild($keyValue);

        // Calculate hash of KeyInfo
        $canonicalizedKeyInfo = $this->canonicalizeElement($this->keyInfoElement, 'ds:KeyInfo', ['xmlns:ds']);
        $this->hashKeyInfo = $this->sha1Base64($canonicalizedKeyInfo);

        return $this->keyInfoElement;
    }

    /**
     * Create XAdES SignedProperties element with all its child elements
     */
    private function createSignedProperties(): DOMElement
    {
        $this->signedPropertiesElement = $this->domDocument->createElement('xades:SignedProperties');
        $this->signedPropertiesElement->setAttribute('Id', 'SignedProperties-'.$this->randomNumbers['signedProperties']);

        // SignedSignatureProperties
        $signedSignatureProperties = $this->domDocument->createElement('xades:SignedSignatureProperties');

        // SigningTime
        $signingTime = $this->domDocument->createElement('xades:SigningTime');
        $signingTime->nodeValue = $this->signingTime;
        $signedSignatureProperties->appendChild($signingTime);

        // SigningCertificate
        $signingCertificate = $this->domDocument->createElement('xades:SigningCertificate');
        $cert = $this->domDocument->createElement('xades:Cert');

        $certDigest = $this->domDocument->createElement('xades:CertDigest');
        $digestMethod = $this->domDocument->createElement('ds:DigestMethod');
        $digestMethod->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        $certDigest->appendChild($digestMethod);

        // Add DigestValue for certificate digest
        $digestValue = $this->domDocument->createElement('ds:DigestValue');

        // Calculate SHA1 hash of certificate in DER format
        $certificateDecoded = base64_decode($this->certificate->getCertificateContent(), true);
        $digestValue->nodeValue = $this->sha1Base64($certificateDecoded);
        $certDigest->appendChild($digestValue);
        $cert->appendChild($certDigest);

        $issuerSerial = $this->domDocument->createElement('xades:IssuerSerial');

        // Add X509IssuerName for certificate issuer name
        $x509IssuerName = $this->domDocument->createElement('ds:X509IssuerName');
        $x509IssuerName->nodeValue = $this->certificate->getIssuerName();
        $issuerSerial->appendChild($x509IssuerName);

        // Add X509SerialNumber for certificate serial number
        $x509SerialNumber = $this->domDocument->createElement('ds:X509SerialNumber');
        $x509SerialNumber->nodeValue = $this->certificate->getSerialNumber();
        $issuerSerial->appendChild($x509SerialNumber);

        $cert->appendChild($issuerSerial);
        $signingCertificate->appendChild($cert);
        $signedSignatureProperties->appendChild($signingCertificate);

        $this->signedPropertiesElement->appendChild($signedSignatureProperties);

        // SignedDataObjectProperties
        $signedDataObjectProperties = $this->domDocument->createElement('xades:SignedDataObjectProperties');
        $dataObjectFormat = $this->domDocument->createElement('xades:DataObjectFormat');
        $dataObjectFormat->setAttribute('ObjectReference', '#DocumentRef-'.$this->randomNumbers['referenceId']);

        $description = $this->domDocument->createElement('xades:Description');
        $description->nodeValue = 'Firma digital';
        $dataObjectFormat->appendChild($description);

        $mimeType = $this->domDocument->createElement('xades:MimeType');
        $mimeType->nodeValue = 'text/xml';
        $dataObjectFormat->appendChild($mimeType);

        $encoding = $this->domDocument->createElement('xades:Encoding');
        $encoding->nodeValue = 'UTF-8';
        $dataObjectFormat->appendChild($encoding);

        $signedDataObjectProperties->appendChild($dataObjectFormat);
        $this->signedPropertiesElement->appendChild($signedDataObjectProperties);

        // Canonicalize SignedProperties and generate its hash
        $canonicalizedSignedProperties = $this->canonicalizeElement($this->signedPropertiesElement, 'xades:SignedProperties');
        $this->hashSignedProperties = $this->sha1Base64($canonicalizedSignedProperties);

        return $this->signedPropertiesElement;
    }

    /**
     * Create the SignedInfo element
     */
    private function createSignedInfo(): DOMElement
    {
        $this->signedInfoElement = $this->domDocument->createElement('ds:SignedInfo');
        $this->signedInfoElement->setAttribute('Id', 'SignedInfo-'.$this->randomNumbers['signedInfo']);

        // CanonicalizationMethod
        $canonicalizationMethod = $this->domDocument->createElement('ds:CanonicalizationMethod');
        $canonicalizationMethod->setAttribute('Algorithm', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315');
        $this->signedInfoElement->appendChild($canonicalizationMethod);

        // SignatureMethod
        $signatureMethod = $this->domDocument->createElement('ds:SignatureMethod');
        $signatureMethod->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1');
        $this->signedInfoElement->appendChild($signatureMethod);

        // Reference to comprobante (root element)
        $referenceInvoice = $this->domDocument->createElement('ds:Reference');
        $referenceInvoice->setAttribute('Id', 'DocumentRef-'.$this->randomNumbers['referenceId']);
        $referenceInvoice->setAttribute('URI', '#comprobante');

        $transformsInvoice = $this->domDocument->createElement('ds:Transforms');
        $transformInvoice = $this->domDocument->createElement('ds:Transform');
        $transformInvoice->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');
        $transformsInvoice->appendChild($transformInvoice);
        $referenceInvoice->appendChild($transformsInvoice);

        $digestMethodInvoice = $this->domDocument->createElement('ds:DigestMethod');
        $digestMethodInvoice->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        $referenceInvoice->appendChild($digestMethodInvoice);

        $digestValueInvoice = $this->domDocument->createElement('ds:DigestValue');
        $digestValueInvoice->nodeValue = $this->hashComprobante;
        $referenceInvoice->appendChild($digestValueInvoice);

        // Add ReferenceInvoice to SignedInfo
        $this->signedInfoElement->appendChild($referenceInvoice);

        // Reference to SignedProperties
        $referenceSignedProperties = $this->domDocument->createElement('ds:Reference');
        $referenceSignedProperties->setAttribute('Id', 'SignedPropertiesRef-'.$this->randomNumbers['signedPropertiesId']);
        $referenceSignedProperties->setAttribute('Type', 'http://uri.etsi.org/01903#SignedProperties');
        $referenceSignedProperties->setAttribute('URI', '#SignedProperties-'.$this->randomNumbers['signedProperties']);

        $digestMethodSignedProperties = $this->domDocument->createElement('ds:DigestMethod');
        $digestMethodSignedProperties->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        $referenceSignedProperties->appendChild($digestMethodSignedProperties);

        $digestValueSignedProperties = $this->domDocument->createElement('ds:DigestValue');
        $digestValueSignedProperties->nodeValue = $this->hashSignedProperties;
        $referenceSignedProperties->appendChild($digestValueSignedProperties);

        // Add ReferenceSignedProperties to SignedInfo
        $this->signedInfoElement->appendChild($referenceSignedProperties);

        // Reference to KeyInfo
        $referenceCertificate = $this->domDocument->createElement('ds:Reference');
        $referenceCertificate->setAttribute('Id', 'CertificateRef-'.$this->randomNumbers['certificateId']);
        $referenceCertificate->setAttribute('URI', '#Certificate-'.$this->randomNumbers['certificate']);

        $digestMethodCertificate = $this->domDocument->createElement('ds:DigestMethod');
        $digestMethodCertificate->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
        $referenceCertificate->appendChild($digestMethodCertificate);

        $digestValueCertificate = $this->domDocument->createElement('ds:DigestValue');
        $digestValueCertificate->nodeValue = $this->hashKeyInfo;
        $referenceCertificate->appendChild($digestValueCertificate);

        // Add ReferenceCertificate to SignedInfo
        $this->signedInfoElement->appendChild($referenceCertificate);

        return $this->signedInfoElement;
    }

    /**
     * Create the SignatureValue element
     */
    private function createSignatureValue(): DOMElement
    {
        $this->signatureValueElement = $this->domDocument->createElement('ds:SignatureValue');
        $this->signatureValueElement->setAttribute('Id', 'SignatureValue-'.$this->randomNumbers['signatureValue']);

        // Canonicalize SignedInfo
        $canonicalized = $this->canonicalizeElement($this->signedInfoElement, 'ds:SignedInfo', ['xmlns:ds']);

        $privateKey = openssl_pkey_get_private($this->certificate->getPrivateKeyPem());
        if (! $privateKey) {
            throw new CertificateException('Failed to load private key');
        }

        $signature = '';
        if (! openssl_sign($canonicalized, $signature, $privateKey, OPENSSL_ALGO_SHA1)) {
            throw new CertificateException('Failed to create digital signature');
        }

        $this->signatureValueElement->nodeValue = base64_encode($signature);

        return $this->signatureValueElement;
    }

    /**
     * Get hash of comprobante element
     */
    private function getHashComprobante(): string
    {
        $root = $this->domDocument->documentElement;
        if ($root === null) {
            throw new SignerException('El documento XML no tiene elemento raíz.');
        }

        // Misma referencia que SignedInfo (URI="#comprobante"): digest del elemento raíz.
        $canonicalized = $root->C14N(false, false, null);

        return $this->sha1Base64($canonicalized);
    }

    /**
     * Canonicalize an element with proper namespaces
     */
    private function canonicalizeElement(DOMElement $element, string $tagName, array $namespaces = []): string
    {
        $replace = "<{$tagName} {$this->getNamespaces($namespaces)} ";
        $xmlWithNamespaces = str_replace("<{$tagName} ", $replace, $this->domDocument->saveXML($element));

        $tempDoc = new DOMDocument($this->version, $this->encoding);
        $tempDoc->loadXML($xmlWithNamespaces);

        // Apply C14N to the entire document
        return $tempDoc->C14N();
    }

    /**
     * Get namespaces string for element
     */
    private function getNamespaces(array $namespaces = []): string
    {
        // If no specific namespaces provided, use all available namespaces
        if (empty($namespaces)) {
            $selectedNamespaces = $this->ns;
        } else {
            // Filter the class namespaces based on provided keys
            $selectedNamespaces = array_intersect_key($this->ns, array_flip($namespaces));
        }

        return $this->joinArray($selectedNamespaces);
    }

    /**
     * Join array elements into namespace declarations string
     */
    private function joinArray(array $array, bool $formatNS = true, string $join = ' '): string
    {
        return implode($join, array_map(function ($value, $key) use ($formatNS) {
            return ($formatNS) ? "{$key}=\"$value\"" : "{$key}=$value";
        }, $array, array_keys($array)));
    }

    /**
     * Calculate SHA1 hash and encode to base64
     */
    private function sha1Base64(string $text): string
    {
        return base64_encode(sha1($text, true));
    }

    /**
     * Generate the 8 random numbers required for XAdES structure
     */
    private function generateRandomNumbers(): void
    {
        $this->randomNumbers = [
            'certificate' => $this->generateUUID(),
            'certificateId' => $this->generateUUID(),
            'signature' => $this->generateUUID(),
            'signedProperties' => $this->generateUUID(),
            'signedInfo' => $this->generateUUID(),
            'signedPropertiesId' => $this->generateUUID(),
            'referenceId' => $this->generateUUID(),
            'signatureValue' => $this->generateUUID(),
            'object' => $this->generateUUID(),
        ];
    }

    /**
     * Get signing time in ISO 8601 format with time zone offset
     */
    private function getSigningTime(): string
    {
        $now = new DateTime('now', new DateTimeZone('America/Guayaquil'));

        return $now->format('Y-m-d\TH:i:sP');
    }

    /**
     * Generate a UUIDv4
     */
    private function generateUUID(): string
    {
        $uuid = Uuid::uuid4();

        return $uuid->toString();
    }
}
