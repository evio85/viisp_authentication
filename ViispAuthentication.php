<?php

/**
 * User: Evaldas
 * Date: 2015-11-23
 * Time: 16:13
 */
class ViispAuthentication
{
    public static $viisp_request_endpoint = "https://www.epaslaugos.lt/portal-test/authenticationServices/auth";
    public static $viisp_soap_endpoint = "https://www.epaslaugos.lt/portal-test/authenticationServices/auth";
    public static $private_key_path = 'file://resources/testKey.pem';

    protected static $soap_req = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:aut="http://www.epaslaugos.lt/services/authentication" xmlns:xd="http://www.w3.org/2000/09/xmldsig#">
   <soapenv:Header/>
   <soapenv:Body>{xml}</soapenv:Body>
</soapenv:Envelope>
';

    protected static $private_key_id = null;


    /**
     * Gaunamas autorizacijos ticket'as
     * @return string
     */
    public static function getAuthenticationTicket(){
        $ticketDom = static::generateTicketDom("VSID000000000113", "kryptis_node_001", "aut");
        static::sign($ticketDom->firstChild);

        if($resp = static::sendSoap($ticketDom, "/authenticationServiceProvider/initAuthentication")){
            $respXml = simplexml_load_string($resp);
            $respXml->registerXPathNamespace('authentication', 'http://www.epaslaugos.lt/services/authentication');
            if($elemets = $respXml->xpath("//authentication:ticket") AND count($elemets)){
                return $elemets[0]->__toString();
            }else{
                static::debugXml($resp);
            }
        }
    }


    /**
     * Generuojamas xml'as ticketui gauti
     *
     * @param $pid
     * @param string $nodeId
     * @param string $namespace
     * @param string $postbackUrl
     * @param string $correlationData
     * @param array $authenticationProviders
     * @param array $authenticationAttributes
     * @param array $userInformations
     * @return DOMDocument
     */
    protected static function generateTicketDom(
        $pid,
        $nodeId = "uniqueNodeId",
        $namespace="authentication",
        $postbackUrl = "https://localhost",
        $correlationData = "correlationData",
        $authenticationProviders = null,
        $authenticationAttributes = null,
        $userInformations = null

    ){
        if(empty($authenticationProviders)){
            $authenticationProviders = ["auth.lt.identity.card", "auth.lt.bank", "auth.signatureProvider", "auth.login.pass"];
        }
        if(empty($authenticationAttributes)){
            $authenticationAttributes = ["lt-personal-code", "lt-company-code"];
        }
        if(empty($userInformations)){
            $userInformations = ["firstName", "lastName", "companyName"];
        }

        $dom = new DOMDocument('1.0', 'utf-8');
        $root = $dom->createElementNS("http://www.epaslaugos.lt/services/authentication", "$namespace:authenticationRequest");
        $root->setAttribute("id", $nodeId);
        $pid = $dom->createElement("$namespace:pid", $pid);
        $root->appendChild($pid);
        foreach($authenticationProviders as $authenticationProvider){
            $authenticationProvider_el = $dom->createElement("$namespace:authenticationProvider", $authenticationProvider);
            $root->appendChild($authenticationProvider_el);
        }
        foreach($authenticationAttributes as $authenticationAttribute){
            $authenticationAttribute_el = $dom->createElement("$namespace:authenticationAttribute", $authenticationAttribute);
            $root->appendChild($authenticationAttribute_el);
        }
        foreach($userInformations as $userInformation){
            $userInformation_el = $dom->createElement("$namespace:userInformation", $userInformation);
            $root->appendChild($userInformation_el);
        }
        $postbackUrl_el = $dom->createElement("$namespace:postbackUrl", $postbackUrl);
        $root->appendChild($postbackUrl_el);
        $customData_el = $dom->createElement("$namespace:customData", $correlationData);
        $root->appendChild($customData_el);

        $dom->appendChild($root);
        return $dom;
    }

    /**
     * Pasirasomas xml'as
     *
     * @param DOMElement $node
     * @return DOMElement
     */
    protected static function sign(DOMElement $node){

        static::$private_key_id = openssl_pkey_get_private(static::$private_key_path);

        $signInfo_el = static::getSignInfo($node);
        $signInfo_el->removeAttribute("xmlns");
        $signature_el = $node->ownerDocument->createElement("Signature");
        $signature_el->setAttribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");
        $signature_el->appendChild($signInfo_el);
        $node->appendChild($signature_el);

        $signatureValue_el = static::getSignatureValue($signInfo_el);
        $signature_el->appendChild($signatureValue_el);
        $signInfo_el->removeAttributeNS("http://www.w3.org/2000/09/xmldsig#", '');
        $signInfo_el->removeAttributeNS("http://www.epaslaugos.lt/services/authentication", "authentication");

        $keyInfo_el = static::getKeyInfo($signature_el);
        $signature_el->appendChild($keyInfo_el);

        openssl_free_key(static::$private_key_id);
        static::$private_key_id = null;

        $node->setAttribute("xmlns:dsig", "http://www.w3.org/2000/09/xmldsig#");

        return $node;
    }

    /**
     * Siunciamas soap requestas
     *
     * @param DOMDocument $dom
     * @param $action
     * @return mixed
     */
    protected static function sendSoap(DOMDocument $dom, $action){
        $soap_req = str_replace("{xml}", $dom->saveHTML(), static::$soap_req);

        $contextData = array (
            'Connection' => 'Keep-Alive',
            'Accept-Encoding' => 'gzip,deflate',
            'Content-Type' => 'text/xml;charset=UTF-8',
            'SOAPAction' => static::$viisp_soap_endpoint . $action,
            'Content-Length' => strlen($soap_req),
            'Host' => 'www.epaslaugos.lt',
            'User-Agent' => 'Apache-HttpClient/4.1.1 (java 1.5)'
        );

        $soap_do = curl_init();
        curl_setopt($soap_do, CURLOPT_URL, static::$viisp_request_endpoint);
        curl_setopt($soap_do, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($soap_do, CURLOPT_TIMEOUT, 10);
        curl_setopt($soap_do, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($soap_do, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($soap_do, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($soap_do, CURLOPT_POST, true);
        curl_setopt($soap_do, CURLOPT_POSTFIELDS, $soap_req);
        //curl_setopt($soap_do, CURLOPT_HTTPHEADER, $contextData);
        $resp = curl_exec($soap_do);
        return $resp;
    }

    /**
     * Sugeneruojamas SignInfo xml
     *
     * @param DOMNode $node
     * @return DOMElement
     */
    protected static function getSignInfo(DOMElement $node){
        $dom = $node->ownerDocument;

        $signedInfo_el = $dom->createElement("SignedInfo");

        $signedInfo_el->setAttribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");
        $signedInfo_el->setAttribute("xmlns:{$node->prefix}", $node->namespaceURI);

        $CanonicalizationMethod_el = $dom->createElement("CanonicalizationMethod");

        $CanonicalizationMethod_el->setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");

        $InclusiveNamespaces_el = $dom->createElement("InclusiveNamespaces");
        $InclusiveNamespaces_el->setAttribute("xmlns", "http://www.w3.org/2001/10/xml-exc-c14n#");
        $InclusiveNamespaces_el->setAttribute("PrefixList", $node->prefix);
        $CanonicalizationMethod_el->appendChild($InclusiveNamespaces_el);

        $signedInfo_el->appendChild($CanonicalizationMethod_el);

        $SignatureMethod_el = $dom->createElement("SignatureMethod");
        $SignatureMethod_el->setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        $signedInfo_el->appendChild($SignatureMethod_el);

        $Reference_el = $dom->createElement("Reference");
        $Reference_el->setAttribute("URI", "#" . $node->getAttribute("id"));

        $Transforms_el = $dom->createElement("Transforms");
        $Transform_el_1 =  $dom->createElement("Transform");
        $Transform_el_1->setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature");
        $Transforms_el->appendChild($Transform_el_1);

        $Transform_el_2 =  $dom->createElement("Transform");
        $Transform_el_2->setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
        $Transform_el_2->appendChild($InclusiveNamespaces_el->cloneNode());
        $Transforms_el->appendChild($Transform_el_2);
        $Reference_el->appendChild($Transforms_el);

        $DigestMethod_el = $dom->createElement("DigestMethod");
        $DigestMethod_el->setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1");
        $Reference_el->appendChild($DigestMethod_el);

        $digestValue = base64_encode(hash("sha1",static::canonicalize($node), true));
        $DigestValue_el = $dom->createElement("DigestValue", $digestValue);
        $Reference_el->appendChild($DigestValue_el);

        $signedInfo_el->appendChild($Reference_el);

        return $signedInfo_el;
    }

    protected static function canonicalize(DOMElement $node)
    {
        $canonicalized = $node->C14N(true, false, null);
        return $canonicalized;
    }

    /**
     * Sugeneruojamas SignatureValue
     *
     * @param DOMElement $signInfo
     * @return DOMElement
     */
    protected static function getSignatureValue(DOMElement $signInfo){
        $dom = $signInfo->ownerDocument;
        $canonicalized = static::canonicalize($signInfo);

        openssl_sign($canonicalized, $signature, static::$private_key_id, OPENSSL_ALGO_SHA1);
        $signatureValue = chunk_split(base64_encode($signature));
        $SignatureValue_el = $dom->createElement("SignatureValue", $signatureValue);
        $dom->appendChild($SignatureValue_el);
        return $SignatureValue_el;
    }

    /**
     * Sugeneruojamas KeyInfo
     *
     * @param DOMElement $signature
     * @return DOMElement
     */
    protected static function getKeyInfo(DOMElement $signature){
        $dom = $signature->ownerDocument;
        $KeyInfo_el = $dom->createElement("KeyInfo");
        $KeyValue_el = $dom->createElement("KeyValue");
        $RSAKeyValue_el = $dom->createElement("RSAKeyValue");
        $key_details = openssl_pkey_get_details(static::$private_key_id);
        $RSAKeyValue_el->appendChild($dom->createElement("Modulus", chunk_split(base64_encode($key_details['rsa']['n']))));
        $RSAKeyValue_el->appendChild($dom->createElement("Exponent", base64_encode($key_details['rsa']['e'])));
        $KeyValue_el->appendChild($RSAKeyValue_el);
        $KeyInfo_el->appendChild($KeyValue_el);
        return $KeyInfo_el;
    }
    protected function debugXml($xmlString){
        header("Content-type: text/xml");
        die($xmlString);
    }
}
