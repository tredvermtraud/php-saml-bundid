<?php

namespace Ermtraud\Saml2;

class XMLConstructor
{
  public static function buildStruct()
  {
    $doc = new \DOMDocument("1.0", "UTF-8");
    $doc->formatOutput = true;
    $root = $doc->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol', 'saml2p:AuthnRequest');
    $root->setAttribute('Version', '2.0');
    $root->setAttribute('xmlns:saml2', 'urn:oasis:names:tc:SAML:2.0:assertion');
    $doc->appendChild($root);
    return $doc->saveXML();
  }
}
