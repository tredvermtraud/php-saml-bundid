<?php

namespace Ermtraud\Saml2\Abstracts;

use DOMDocument;
use DOMElement;

abstract class RequestAbstractType
{
  protected DOMDocument $doc;
  protected null|DOMElement $issuer;
  protected null|DOMElement $signature;
  protected null|DOMElement $extensions;

  public function __construct(string|null $version = "1.0", string|null $encoding = "UTF-8")
  {
    $this->doc = new DOMDocument($version, $encoding);
    $this->doc->formatOutput = true;
  }

  public function createElementNS(string|null $namespace, string $qualifiedName, string $value = ""): DOMElement
  {
    return $this->doc->createElementNS($namespace, $qualifiedName, $value);
  }

  abstract public function buildStruct();

  public function getXML()
  {
    return $this->doc->saveXML();
  }

  public function getDOC()
  {
    return $this->doc;
  }
}
