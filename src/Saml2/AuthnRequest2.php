<?php

namespace Ermtraud\Saml2;

use DOMDocument;
use Ermtraud\Saml2\Abstracts\RequestAbstractType;

class AuthnRequest2 extends RequestAbstractType
{
  protected bool $requiresSubject = false;
  protected bool $requiresNameIDPolicy = false;
  protected bool $requiresConditions = false;
  protected bool $requiresRequestedAuthnContext = false;
  protected bool $requiresScoping = false;

  public function __construct(private Settings $settings, ?string $version = "1.0", ?string $encoding = "UTF-8")
  {
    parent::__construct($version, $encoding);
  }

  public function buildStruct() {}

  public function buildBundIDStruct(?bool $forceAuthn = false, ?bool $isPassive = false)
  {
    $root = $this->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol', 'saml2p:AuthnRequest');
    $this->doc->appendChild($root);
    $root->setAttribute('AssertionConsumerServiceURL', $this->settings->getSPData()['assertionConsumerService']['url']);
    $root->setAttribute('ProtocolBinding', $this->settings->getSPData()['assertionConsumerService']['binding']);
    $root->setAttribute('Destination', $this->settings->getIdPSSOUrl());
    $root->setAttribute('IssueInstant', Utils::parseTime2SAML(time()));
    $root->setAttribute('ForceAuthn', $forceAuthn ? 'true' : 'false');
    $root->setAttribute('IsPassive', $isPassive ? 'true' : 'false');
    $root->setAttribute('Version', '2.0');
    $root->setAttribute('ID', Utils::generateUniqueID());

    $Issuer = $this->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml2a:Issuer', $this->settings->getSPData()['entityId']);
    $root->appendChild($Issuer);

    /* Extensions */ {
      $Extensions = $this->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol', 'saml2p:Extensions');
      $root->appendChild($Extensions);
      $AuthenticationRequest = $this->createElementNS('https://www.akdb.de/request/2018/09', 'akdb:AuthenticationRequest');
      $Extensions->appendChild($AuthenticationRequest);
      if($this->settings->isDebugActive())
        $AuthenticationRequest->setAttribute('EnableStatusDetail', 'true');
      $AuthenticationRequest->setAttribute('Version', $this->settings->getAttributeConsumingService()['version']);

      /* AuthnMethods */ {
        $AuthnMethods = $this->createElementNS('https://www.akdb.de/request/2018/09', 'akdb:AuthnMethods');
        $AuthenticationRequest->appendChild($AuthnMethods);
        foreach($this->settings->getAuthnMethods() as $qN => $details) {
          $methodElement = $this->createElementNS('https://www.akdb.de/request/2018/09', "akdb:$qN");
          foreach($details as $subName => $attOrVal) {
            if(is_array($attOrVal)) {
              $subEl = $this->createElementNS('https://www.akdb.de/request/2018/09', "akdb:$subName");
              foreach($attOrVal as $k => $v) {
                if(is_bool($v))
                  $v = $v ? 'true' : 'false';
                $subEl->setAttribute($k, (string)$v);
              }
            } else {
              $text = is_bool($attOrVal) ? ($attOrVal ? 'true' : 'false') : (string)$attOrVal;
              $subEl = $this->createElementNS('https://www.akdb.de/request/2018/09', "akdb:$subName", $text);
            }
            $methodElement->appendChild($subEl);
          }
          $AuthnMethods->appendChild($methodElement);
        }
      }

      /* RequestedAttributes */ {
        $RequestedAttributes = $this->createElementNS('https://www.akdb.de/request/2018/09', 'akdb:RequestedAttributes');
        $AuthenticationRequest->appendChild($RequestedAttributes);
        foreach($this->settings->getRequestedAttributes() as $attribute) {
          $RequestedAttribute = $this->createElementNS('https://www.akdb.de/request/2018/09', 'akdb:RequestedAttribute');
          $RequestedAttribute->setAttribute('Name', $attribute['name']);
          $RequestedAttribute->setAttribute('RequiredAttribute', is_bool($attribute['isRequired']) ? ($attribute['isRequired'] ? 'true' : 'false') : (string)$attribute['isRequired']);
          $RequestedAttributes->appendChild($RequestedAttribute);
        }
      }

      /* DisplayInformation */ {
        $DisplayInformation = $this->createElementNS('https://www.akdb.de/request/2018/09', 'akdb:DisplayInformation');
        $AuthenticationRequest->appendChild($DisplayInformation);
        $di = $this->settings->getDisplayInformation();

        $Version = $this->createElementNS('https://www.akdb.de/request/2018/09/classic-ui/v1', 'classic-ui:Version');
        $DisplayInformation->appendChild($Version);
        $Purpose = $this->createElementNS('https://www.akdb.de/request/2018/09/classic-ui/v1', 'classic-ui:Purpose', $di['Purpose']);
        $Version->appendChild($Purpose);
        $OrganizationDisplayName = $this->createElementNS('https://www.akdb.de/request/2018/09/classic-ui/v1', 'classic-ui:OrganizationDisplayName', $di['OrganizationDisplayName']);
        $Version->appendChild($OrganizationDisplayName);
        $Lang = $this->createElementNS('https://www.akdb.de/request/2018/09/classic-ui/v1', 'classic-ui:Lang', $di['Lang']);
        $Version->appendChild($Lang);
        $BackURL = $this->createElementNS('https://www.akdb.de/request/2018/09/classic-ui/v1', 'classic-ui:BackURL', $di['BackURL']);
        $Version->appendChild($BackURL);
        $OnlineServiceId = $this->createElementNS('https://www.akdb.de/request/2018/09/classic-ui/v1', 'classic-ui:OnlineServiceId', $di['OnlineServiceId']);
        $Version->appendChild($OnlineServiceId);
      }

    }

    /* RequestedAuthnContext */ {
      $RequestedAuthnContext = $this->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol', 'saml2p:RequestedAuthnContext');
      $root->appendChild($RequestedAuthnContext);
      $RequestedAuthnContext->setAttribute('Comparison', $this->settings->getSecurityData()['requestedAuthnContextComparison']);
      foreach($this->settings->getSecurityData()['requestedAuthnContext'] as $context) {
        $AuthnContextClassRef = $this->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml2a:AuthnContextClassRef', $context);
      }
      $RequestedAuthnContext->appendChild($AuthnContextClassRef);
    }
  }
}
