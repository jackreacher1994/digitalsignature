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

    //Digest algorithm for digesting
    protected $digestMethod = self::DIGEST_SHA1;

    //Sign algorithm to sign with the private key
    protected $cryptoAlgorithm = self::RSA_ALGORITHM;

    //XML standalone declaration
    protected $standalone = false;

    //Namespace prefix for each node name
    protected $nodeNsPrefix = 'dsig:';

    //Set the namespace prefix for each node name
    public function setNodeNsPrefix($prefix)
    {
        if (is_string($prefix) && strlen($prefix)) {
            $this->nodeNsPrefix = rtrim($prefix, ':') . ':';
        } else {
            $this->nodeNsPrefix = '';
        }

        return $this;
    }

    //Forces the signed document to be standalone
    public function forceStandalone()
    {
        $this->standalone = true;
        return $this;
    }

    //Canonicalize a DOM document or a single DOM node
    protected function canonicalize(\DOMNode $object)
    {
        $options = $this->c14nOptionMapping[$this->canonicalMethod];

        $c14nData = $object->C14N($options['exclusive'], $options['withComments']);

        if (is_string($c14nData) && strlen($c14nData)) {
            return $c14nData;
        }

        //If the canonicalization process failed
        trigger_error('Unable to canonicalize the DOM document!', E_USER_ERROR);
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

    //Set the canonical method to canonicalize the document
    public function setCanonicalMethod($method)
    {
        if (array_key_exists($method, $this->c14nOptionMapping)) {
            $this->canonicalMethod = $method;
        } else {
            trigger_error('The chosen canonical method is not supported!', E_USER_WARNING);
            return false;
        }

        return $this;
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
        $this->doc = new \DOMDocument('1.0', 'UTF-8');
        $this->doc->xmlStandalone = $this->standalone;

        $signature = $this->doc->createElementNS(self::XML_DSIG_NS, $this->nodeNsPrefix . 'Signature');
        $this->doc->appendChild($signature);

        $signedInfo = $this->doc->createElement($this->nodeNsPrefix . 'SignedInfo');
        $signature->appendChild($signedInfo);

        $c14nMethod = $this->doc->createElement($this->nodeNsPrefix . 'CanonicalizationMethod');
        $c14nMethod->setAttribute('Algorithm', $this->canonicalMethod);
        $signedInfo->appendChild($c14nMethod);

        $sigMethod = $this->doc->createElement($this->nodeNsPrefix . 'SignatureMethod');
        $sigMethod->setAttribute('Algorithm', $this->digestSignatureAlgoMapping[$this->cryptoAlgorithm][$this->digestMethod]);
        $signedInfo->appendChild($sigMethod);

        $sigValue = $this->doc->createElement($this->nodeNsPrefix . 'SignatureValue');
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
            throw new \UnexpectedValueException('Vui lòng hoàn tất form nhập liệu!');
        }

        $data = $this->doc->importNode($data, true);

        $object = $this->doc->createElement($this->nodeNsPrefix . 'Object');
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

    public function addReference(\DOMNode $node, $uri)
    {
        $signedInfo = $this->doc->getElementsByTagName($this->nodeNsPrefix . 'SignedInfo')->item(0);
        $reference = $this->doc->createElement($this->nodeNsPrefix . 'Reference');
        $signedInfo->appendChild($reference);

        if (is_string($uri) && strlen($uri)) {
            $uri = '#' . $uri;
            $reference->setAttribute('URI', $uri);
        }

        $digestMethod = $this->doc->createElement($this->nodeNsPrefix . 'DigestMethod');
        $digestMethod->setAttribute('Algorithm', $this->digestMethodUriMapping[$this->digestMethod]);
        $reference->appendChild($digestMethod);

        try {
            $c14nData = $this->canonicalize($node);
        } catch (\UnexpectedValueException $e) {
            throw $e;
        }

        $referenceDigest = $this->calculateDigest($c14nData);

        $digestValue = $this->doc->createElement($this->nodeNsPrefix . 'DigestValue', $referenceDigest);
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
        $signedInfo = $this->doc->getElementsByTagName($this->nodeNsPrefix . 'SignedInfo')->item(0);
        if (is_null($signedInfo)) {
            throw new \UnexpectedValueException('Unabled to find the SignedInfo node!');
        }

        $c14nSignedInfo = $this->canonicalize($signedInfo);
        //var_dump($c14nSignedInfo);

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

        $signatureNode = $this->doc->getElementsByTagName($this->nodeNsPrefix . 'SignatureValue')->item(0);
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

    public function getSignatureValue()
    {
        $signatureValue = $this->doc->getElementsByTagName($this->nodeNsPrefix . 'SignatureValue')->item(0);
        if (is_null($signatureValue)) {
            trigger_error('Unabled to find the SignatureValue node!', E_USER_ERROR);
            return false;
        }
        return $signatureValue->nodeValue;
    }

    public function getSignedInfo()
    {
        $signedInfo = $this->doc->getElementsByTagName($this->nodeNsPrefix . 'SignedInfo')->item(0);
        if (is_null($signedInfo)) {
            trigger_error('Unabled to find the SignedInfo node!', E_USER_ERROR);
            return false;
        }

        $c14nSignedInfo = $this->canonicalize($signedInfo);
        return $c14nSignedInfo;
    }

    public function verify($c14nSignedInfo, $signatureValue)
    {
        $this->setCryptoAlgorithm(config('signature.signature-method'));
        $this->setDigestMethod(config('signature.digest-method'));
        $this->forceStandalone();

        if (is_null($this->publicKey)) {
            trigger_error('Cannot verify the digital signature without the public key!', E_USER_WARNING);
            return false;
        }

        $signature = base64_decode($signatureValue);

        return 1 === openssl_verify($c14nSignedInfo, $signature, $this->publicKey, $this->openSSLAlgoMapping[$this->digestMethod]);
    }

}