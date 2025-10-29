<?php
/**
 * This file is part of php-saml.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @package OneLogin
 * @author  Sixto Martin <sixto.martin.garcia@gmail.com>
 * @license MIT https://github.com/SAML-Toolkits/php-saml/blob/master/LICENSE
 * @link    https://github.com/SAML-Toolkits/php-saml
 */

namespace Ermtraud\Saml2;

use Ermtraud\Saml2\Abstracts\RequestAbstractType;

/**
 * SAML 2 Authentication Request
 */
class AuthnRequest extends RequestAbstractType
{
  /**
   * Object that represents the setting info
   *
   * @var Settings
   */
  protected $_settings;

  /**
   * SAML AuthNRequest ID.
   *
   * @var string
   */
  private $_id;

  /**
   * Constructs the AuthnRequest object.
   *
   * @param Settings $settings SAML Toolkit Settings
   * @param bool $forceAuthn When true the AuthNReuqest will set the ForceAuthn='true'
   * @param bool $isPassive When true the AuthNReuqest will set the Ispassive='true'
   * @param bool $setNameIdPolicy When true the AuthNReuqest will set a nameIdPolicy
   * @param string $nameIdValueReq Indicates to the IdP the subject that should be authenticated
   */
  public function __construct(Settings $settings, $forceAuthn = false, $isPassive = false, $setNameIdPolicy = true, $nameIdValueReq = null)
  {
    parent::__construct("1.0", "UTF-8");
    $this->_settings = $settings;
    $this->_id = Utils::generateUniqueID();

    $this->buildStruct($forceAuthn, $isPassive, $setNameIdPolicy, $nameIdValueReq);
  }

  /**
   * Returns deflated, base64 encoded, unsigned AuthnRequest.
   *
   * @param bool|null $deflate Whether or not we should 'gzdeflate' the request body before we return it.
   *
   * @return string
   */
  public function getRequest($deflate = null)
  {
    $subject = $this->getXML();

    if(is_null($deflate)) {
      $deflate = $this->_settings->shouldCompressRequests();
    }

    if($deflate) {
      $subject = gzdeflate($this->getXML());
    }

    $base64Request = base64_encode($subject);
    return $base64Request;
  }

  /**
   * Returns the AuthNRequest ID.
   *
   * @return string
   */
  public function getId()
  {
    return $this->_id;
  }

  public function buildStruct(?bool $forceAuthn = false, ?bool $isPassive = false, ?bool $setNameIdPolicy = true, ?string $nameIdValueReq = null)
  {
    $root = $this->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol', 'saml2p:AuthnRequest');
    $this->doc->appendChild($root);
    $root->setAttribute('AssertionConsumerServiceURL', $this->_settings->getSPData()['assertionConsumerService']['url']);
    $root->setAttribute('ProtocolBinding', $this->_settings->getSPData()['assertionConsumerService']['binding']);
    $root->setAttribute('Destination', $this->_settings->getIdPSSOUrl());
    $root->setAttribute('IssueInstant', Utils::parseTime2SAML(time()));
    $root->setAttribute('ForceAuthn', $forceAuthn ? 'true' : 'false');
    $root->setAttribute('IsPassive', $isPassive ? 'true' : 'false');
    $root->setAttribute('Version', '2.0');
    $root->setAttribute('ID', $this->getId());

    $Issuer = $this->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml2a:Issuer', $this->_settings->getSPData()['entityId']);
    $root->appendChild($Issuer);

    if(isset($nameIdValueReq)) {
      $nameIDFormat = $this->_settings->getSPData()['NameIDFormat'];
      $Subject = $this->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml2a:Subject');
      $root->appendChild($Subject);
      $NameID = $this->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml2a:NameID', $nameIdValueReq);
      $Subject->appendChild($NameID);
      $NameID->setAttribute('Format', $nameIDFormat);
      $SubjectConfirmation = $this->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml2a:SubjectConfirmation', '');
      $Subject->appendChild($SubjectConfirmation);
      $SubjectConfirmation->setAttribute('Method', 'urn:oasis:names:tc:SAML:2.0:cm:bearer');
    }

    if($setNameIdPolicy) {
      $nameIDFormat = $this->_settings->getSPData()['NameIDFormat'];
      $security = $this->_settings->getSecurityData();
      if(isset($security['wantNameIdEncrypted']) && $security['wantNameIdEncrypted']) {
        $nameIDFormat = Constants::NAMEID_ENCRYPTED;
      }

      $NameIDPolicy = $this->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml2a:NameIDPolicy');
      $root->appendChild($NameIDPolicy);
      $NameIDPolicy->setAttribute('Format', $nameIDFormat);
      $NameIDPolicy->setAttribute('AllowCreate', 'true');
    }

    /* Extensions */ {
      $Extensions = $this->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol', 'saml2p:Extensions');
      $root->appendChild($Extensions);
      $AuthenticationRequest = $this->createElementNS('https://www.akdb.de/request/2018/09', 'akdb:AuthenticationRequest');
      $Extensions->appendChild($AuthenticationRequest);
      if($this->_settings->isDebugActive())
        $AuthenticationRequest->setAttribute('EnableStatusDetail', 'true');
      $AuthenticationRequest->setAttribute('Version', $this->_settings->getAttributeConsumingService()['version']);

      /* AuthnMethods */ {
        $AuthnMethods = $this->createElementNS('https://www.akdb.de/request/2018/09', 'akdb:AuthnMethods');
        $AuthenticationRequest->appendChild($AuthnMethods);
        foreach($this->_settings->getAuthnMethods() as $qN => $details) {
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
        foreach($this->_settings->getRequestedAttributes() as $attribute) {
          $RequestedAttribute = $this->createElementNS('https://www.akdb.de/request/2018/09', 'akdb:RequestedAttribute');
          $RequestedAttribute->setAttribute('Name', $attribute['name']);
          $RequestedAttribute->setAttribute('RequiredAttribute', is_bool($attribute['isRequired']) ? ($attribute['isRequired'] ? 'true' : 'false') : (string)$attribute['isRequired']);
          $RequestedAttributes->appendChild($RequestedAttribute);
        }
      }

      /* DisplayInformation */ {
        $DisplayInformation = $this->createElementNS('https://www.akdb.de/request/2018/09', 'akdb:DisplayInformation');
        $AuthenticationRequest->appendChild($DisplayInformation);
        $di = $this->_settings->getDisplayInformation();

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
      $RequestedAuthnContext->setAttribute('Comparison', $this->_settings->getSecurityData()['requestedAuthnContextComparison']);
      foreach($this->_settings->getSecurityData()['requestedAuthnContext'] as $context) {
        $AuthnContextClassRef = $this->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml2a:AuthnContextClassRef', $context);
      }
      $RequestedAuthnContext->appendChild($AuthnContextClassRef);
    }
  }
}
