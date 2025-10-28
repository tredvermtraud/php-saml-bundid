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

/**
 * SAML 2 Authentication Request
 */
class AuthnRequest
{
  /**
   * Object that represents the setting info
   *
   * @var Settings
   */
  protected $_settings;

  /**
   * SAML AuthNRequest string
   *
   * @var string
   */
  private $_authnRequest;

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
    $this->_settings = $settings;

    $authnrequest = new AuthnRequest2($settings);
    $authnrequest->buildStruct($forceAuthn, $isPassive, $setNameIdPolicy, $nameIdValueReq);
    $this->_authnRequest = $authnrequest->getXML();
    $this->_id = $authnrequest->getId();
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
    $subject = $this->_authnRequest;

    if(is_null($deflate)) {
      $deflate = $this->_settings->shouldCompressRequests();
    }

    if($deflate) {
      $subject = gzdeflate($this->_authnRequest);
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

  /**
   * Returns the XML that will be sent as part of the request
   *
   * @return string
   */
  public function getXML()
  {
    return $this->_authnRequest;
  }
}
