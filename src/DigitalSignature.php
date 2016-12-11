<?php

namespace QuanNH\DigitalSignature;

class DigitalSignature
{
    //Namespace
    const XML_DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

    //Digest algorithm
    const DIGEST_SHA1 = 'sha1';
    const DIGEST_SHA256 = 'sha256';
    const DIGEST_SHA512 = 'sha512';
    const DIGEST_RIPEMD160 = 'ripmed160';

    //Canonicalization method
    const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    const C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    const C14N_EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    const C14N_EXCLUSIVE_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    //Signature method
    const RSA_ALGORITHM = 1;
    const DSA_ALGORITHM = 2;
    const ECDSA_ALGORITHM = 3;
    const HMAC_ALGORITHM = 4;

    //Transform method
    const TRANS = 'http://www.w3.org/2006/12/xml-c14n11';

    //Mapping digest algorithm to its W3 spec URI
    protected $digestMethodUriMapping = array(
        self::DIGEST_SHA1 => 'http://www.w3.org/2000/09/xmldsig#sha1',
        self::DIGEST_SHA256 => 'http://www.w3.org/2001/04/xmlenc#sha256',
        self::DIGEST_SHA512 => 'http://www.w3.org/2001/04/xmlenc#sha512',
        self::DIGEST_RIPEMD160 => 'http://www.w3.org/2001/04/xmlenc#ripemd160',
    );

    //Mapping digest method to its OpenSSL hashing algorithm
    protected $openSSLAlgoMapping = array(
        self::DIGEST_SHA1 => OPENSSL_ALGO_SHA1,
        self::DIGEST_SHA256 => OPENSSL_ALGO_SHA256,
        self::DIGEST_SHA512 => OPENSSL_ALGO_SHA512,
        self::DIGEST_RIPEMD160 => OPENSSL_ALGO_RMD160,
    );

    //Mapping sign algorithm to its W3 spec URIs
    protected $digestSignatureAlgoMapping = array(
        self::RSA_ALGORITHM => array(
            self::DIGEST_SHA1 => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            self::DIGEST_SHA256 => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            self::DIGEST_SHA512 => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
            self::DIGEST_RIPEMD160 => 'http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160',
        ),
        self::DSA_ALGORITHM => array(
            self::DIGEST_SHA1 => 'http://www.w3.org/2000/09/xmldsig#dsa-sha1',
            self::DIGEST_SHA256 => 'http://www.w3.org/2009/xmldsig11#dsa-sha256',
        ),
        self::ECDSA_ALGORITHM => array(
            self::DIGEST_SHA1 => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1',
            self::DIGEST_SHA256 => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
            self::DIGEST_SHA512 => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
            self::DIGEST_RIPEMD160 => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha51',
        ),
        self::HMAC_ALGORITHM => array(
            self::DIGEST_SHA1 => 'http://www.w3.org/2000/09/xmldsig#hmac-sha1',
            self::DIGEST_SHA256 => 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256',
            self::DIGEST_SHA512 => 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha512',
            self::DIGEST_RIPEMD160 => 'http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160',
        ),
    );

    ///Mapping canonicalization attribute, based on the canonicalization method
    protected $c14nOptionMapping = array(
        self::C14N => array('exclusive' => false, 'withComments' => false),
        self::C14N_COMMENTS => array('exclusive' => false, 'withComments' => true),
        self::C14N_EXCLUSIVE => array('exclusive' => true, 'withComments' => false),
        self::C14N_EXCLUSIVE_COMMENTS => array('exclusive' => true, 'withComments' => true),
    );

    //Document to sign
    protected $doc;

    protected $privateKey;
    protected $publicKey;

    //Canonicalization method to canonicalize the document
    protected $canonicalMethod = self::C14N;

    //Transform method to transform data
    protected $transformMethod = self::TRANS;

    //Digest algorithm for digesting
    protected $digestMethod = self::DIGEST_SHA1;

    //Sign algorithm to sign with the private key
    protected $cryptoAlgorithm = self::RSA_ALGORITHM;

    public function _construct()
    {
        $this->setCryptoAlgorithm(config('signature.signature-method'));
        $this->setDigestMethod(config('signature.digest-method'));
    }

    //Canonicalize a single DOM node
    protected function canonicalize(\DOMNode $object)
    {
        $options = $this->c14nOptionMapping[$this->canonicalMethod];

        $c14nData = $object->C14N($options['exclusive'], $options['withComments']);

        if (is_string($c14nData) && strlen($c14nData)) {
            return $c14nData;
        }

        //If the canonicalization process failed
        trigger_error('Unable to canonicalize the DOM node!', E_USER_ERROR);
        return false;
    }

    //Transform a single DOM node
    protected function transform(\DOMNode $object)
    {
        $c14nData = $object->C14N();

        if (is_string($c14nData) && strlen($c14nData)) {
            return $c14nData;
        }

        //If the transform process failed
        trigger_error('Unable to transform the DOM node!', E_USER_ERROR);
        return false;
    }

    protected function checkDigestSupport()
    {
        if (!in_array($this->digestMethod, hash_algos())) {
            trigger_error(sprintf('The current version of PHP does not support the %s hashing algorithm', $this->digestMethod), E_USER_ERROR);
            return false;
        }
    }

    protected function calculateDigest($data)
    {
        $this->checkDigestSupport();

        return base64_encode(hash($this->digestMethod, $data, true));
    }

    //Set the digest method to calculate the digest value of the data
    public function setDigestMethod($method)
    {
        if (array_key_exists($method, $this->openSSLAlgoMapping) &&
            array_key_exists($method, $this->digestMethodUriMapping)
        ) {
            $this->digestMethod = $method;
        } else {
            trigger_error('The chosen digest method is not supported!', E_USER_WARNING);
            return false;
        }

        $this->checkDigestSupport();

        return $this;
    }

    //Set the signature method to sign with the private key
    public function setCryptoAlgorithm($algo)
    {
        if (!array_key_exists($algo, $this->digestSignatureAlgoMapping)) {
            trigger_error('The chosen sign algorithm is not supported!', E_USER_WARNING);
            return false;
        } else if (!array_key_exists($this->digestMethod, $this->digestSignatureAlgoMapping[$algo])) {
            trigger_error('The chosen sign algorithm does not support the chosen digest method!', E_USER_WARNING);
            return false;
        } else {
            $this->cryptoAlgorithm = $algo;
        }

        return $this;
    }

    public function loadPrivateKey($filePath, $passphrase)
    {
        if (!file_exists($filePath) || !is_readable($filePath)) {
            //throw new \UnexpectedValueException(sprintf('Unable to open file "%s"!', $filePath));
            throw new \UnexpectedValueException(sprintf('Không thể mở được tập tin "%s"!', $filePath));
        }

        $key = @file_get_contents($filePath);

        if (!is_string($key) || 0 === strlen($key)) {
            //throw new \UnexpectedValueException(sprintf('File "%s" is empty!', $filePath));
            throw new \UnexpectedValueException(sprintf('Tập tin "%s" không có nội dung!', $filePath));
        }

        $privKey = openssl_pkey_get_private($key, $passphrase);

        if (false === $privKey) {
            //throw new \UnexpectedValueException('Unable to load the private key!');
            throw new \UnexpectedValueException('Chứng thư này không hợp lệ!');
        }

        $this->privateKey = $privKey;

        return true;
    }

    public function loadPublicKey($key)
    {
        $pubKey = openssl_pkey_get_public($key);

        if (false === $pubKey) {
            //throw new \UnexpectedValueException('Unable to load the public key!');
            throw new \UnexpectedValueException('Khóa công khai của người dùng không hợp lệ!');
        }

        $this->publicKey = $pubKey;

        return true;
    }

    //Prepare the XML template
    protected function createXmlStructure()
    {
        $this->doc = new \DOMDocument(config('signature.version'), config('signature.encoding'));
        $this->doc->preserveWhiteSpace = false;
        $this->doc->formatOutput = true;

        $signature = $this->doc->createElementNS(self::XML_DSIG_NS, 'Signature');
        $this->doc->appendChild($signature);

        $signedInfo = $this->doc->createElement('SignedInfo');
        $signature->appendChild($signedInfo);

        $c14nMethod = $this->doc->createElement('CanonicalizationMethod');
        $c14nMethod->setAttribute('Algorithm', $this->canonicalMethod);
        $signedInfo->appendChild($c14nMethod);

        $sigMethod = $this->doc->createElement('SignatureMethod');
        $sigMethod->setAttribute('Algorithm', $this->digestSignatureAlgoMapping[$this->cryptoAlgorithm][$this->digestMethod]);
        $signedInfo->appendChild($sigMethod);

        $sigValue = $this->doc->createElement('SignatureValue');
        $signature->appendChild($sigValue);
    }

    //Append an object to the signed document
    public function addObject($data, $objectId = null)
    {
        if (is_null($this->doc)) {
            $this->createXmlStructure();
        }

        if (is_string($data) && strlen($data)) {
            $data = $this->doc->createTextNode($data);
        } else if (!is_object($data) || !$data instanceof \DOMNode) {
            //throw new \UnexpectedValueException('Digested data must be a non-empty string or DOMNode!');
            throw new \UnexpectedValueException('Vui lòng hoàn tất nhập liệu đơn!');
        }

        $data = $this->doc->importNode($data, true);

        $object = $this->doc->createElement('Object');
        $object->appendChild($data);
        $this->doc->getElementsByTagName('Signature')->item(0)->appendchild($object);

        if (!is_string($objectId) || !strlen($objectId) || is_numeric($objectId[0])) {
            //Generate a random ID
            $objectId = rtrim(base64_encode(mt_rand()), '=');
        }

        $object->setAttribute('ID', $objectId);

        //Object also need to be digested and stored as a reference
        $this->addReference($object, $objectId);

        return true;
    }

    protected function addReference(\DOMNode $node, $uri)
    {
        $signedInfo = $this->doc->getElementsByTagName('SignedInfo')->item(0);
        $reference = $this->doc->createElement('Reference');
        $signedInfo->appendChild($reference);

        if (is_string($uri) && strlen($uri)) {
            $uri = '#' . $uri;
            $reference->setAttribute('URI', $uri);
        }

        $transforms = $this->doc->createElement('Transforms');
        $transform = $this->doc->createElement('Transform');
        $transform->setAttribute('Algorithm', $this->transformMethod);
        $transforms->appendChild($transform);
        $reference->appendChild($transforms);

        $digestMethod = $this->doc->createElement('DigestMethod');
        $digestMethod->setAttribute('Algorithm', $this->digestMethodUriMapping[$this->digestMethod]);
        $reference->appendChild($digestMethod);


        $c14nData = $this->transform($node);
        //var_dump($c14nData);
        //exit(1);

        $referenceDigest = $this->calculateDigest($c14nData);

        $digestValue = $this->doc->createElement('DigestValue', $referenceDigest);
        $reference->appendChild($digestValue);

        return true;
    }

    public function sign()
    {
        if (is_null($this->doc)) {
            trigger_error('No document to sign!', E_USER_ERROR);
            return false;
        }

        //Find the SignedInfo element to sign
        $signedInfo = $this->doc->getElementsByTagName('SignedInfo')->item(0);
        if (is_null($signedInfo)) {
            trigger_error('Unabled to find the SignedInfo node!', E_USER_ERROR);
            return false;
        }
        $c14nSignedInfo = $this->canonicalize($signedInfo);
        //var_dump($c14nSignedInfo);
        //exit(1);

        //Which OpenSSL algorithm to use
        if (!array_key_exists($this->digestMethod, $this->openSSLAlgoMapping)) {
            trigger_error('No OpenSSL algorithm has been defined for the digest algorithm!', E_USER_ERROR);
            return false;
        }

        //Sign the SignedInfo element using the private key
        if (!openssl_sign($c14nSignedInfo, $signature, $this->privateKey, $this->openSSLAlgoMapping[$this->digestMethod])) {
            //throw new \UnexpectedValueException('Unable to sign the document! Error: ' . openssl_error_string());
            throw new \UnexpectedValueException('Không thể ký! Đã xảy ra lỗi: ' . openssl_error_string());
        }
        $signature = base64_encode($signature);
        $signatureNode = $this->doc->getElementsByTagName('SignatureValue')->item(0);
        if (is_null($signatureNode)) {
            trigger_error('Unabled to find the SingatureValue node!', E_USER_ERROR);
            return false;
        }
        $signatureNode->appendChild($this->doc->createTextNode($signature));

        return true;
    }

    //Returns the signed XML document
    public function getSignedDocument()
    {
        return $this->doc->saveXML();
    }

    public function verifySignature($signedDocument)
    {
        if (is_null($this->publicKey)) {
            trigger_error('Cannot verify the digital signature without public key!', E_USER_WARNING);
            return false;
        }

        //Find the SignedInfo element
        $signedInfo = $signedDocument->getElementsByTagNameNS(self::XML_DSIG_NS, 'SignedInfo')->item(0);
        if (is_null($signedInfo)) {
            trigger_error('Unabled to find the SignedInfo node!', E_USER_ERROR);
            return false;
        }
        $c14nSignedInfo = $this->canonicalize($signedInfo);
        //var_dump($c14nSignedInfo);
        //exit(1);

        //Find the signature value to verify
        $signatureValue = $signedDocument->getElementsByTagNameNS(self::XML_DSIG_NS, 'SignatureValue')->item(0);
        if (is_null($signatureValue)) {
            trigger_error('Unabled to find the SignatureValue node!', E_USER_ERROR);
            return false;
        }
        //var_dump($signatureValue->nodeValue);
        //exit(1);
        $signature = base64_decode($signatureValue->nodeValue);

        return 1 === openssl_verify($c14nSignedInfo, $signature, $this->publicKey, $this->openSSLAlgoMapping[$this->digestMethod]);
    }

    protected function getReference($signedDocument, $objectID)
    {
        $references = $signedDocument->getElementsByTagNameNS(self::XML_DSIG_NS, 'Reference');
        if ($references->length == 0) {
            trigger_error('Unabled to find the Reference node!', E_USER_ERROR);
            return false;
        }

        foreach ($references as $reference) {
            $uri = $reference->getAttribute('URI');
            if (substr($uri, 1) === $objectID) {
                return $reference;
            }
        }

        trigger_error('Unabled to find the Reference node with this URI!', E_USER_ERROR);
        return false;
    }

    public function verifyData($signedDocument)
    {
        $objects = $signedDocument->getElementsByTagNameNS(self::XML_DSIG_NS, 'Object');
        if ($objects->length == 0) {
            trigger_error('Unabled to find the Object node!', E_USER_ERROR);
            return false;
        }

        foreach ($objects as $node) {
            $c14nData = $this->transform($node);
            $referenceDigest = $this->calculateDigest($c14nData);

            $objectId = $node->getAttribute('ID');
            $reference = $this->getReference($signedDocument, $objectId);
            $digest = $reference->getElementsByTagName('DigestValue')->item(0);

            if ($referenceDigest !== $digest->nodeValue) {
                return false;
            }
        }

        return true;
    }

    public function getData($signedDocument, $objectID)
    {
        $objects = $signedDocument->getElementsByTagNameNS(self::XML_DSIG_NS, 'Object');
        if ($objects->length == 0) {
            trigger_error('Unabled to find the Object node!', E_USER_ERROR);
            return false;
        }

        foreach ($objects as $object) {
            $id = $object->getAttribute('ID');
            if ($id === $objectID) {
                return $object->nodeValue;
            }
        }

        trigger_error('Unabled to find the Object node with this ID!', E_USER_ERROR);
        return false;
    }

}