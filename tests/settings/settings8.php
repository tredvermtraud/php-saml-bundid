<?php

$settings = [
  'sp' => [
    'entityId' => 'https://online.geve-services.de',
    'assertionConsumerService' => [
      'url' => 'https://online.geve-services.de/saml/acs',
      'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    ],
    'attributeConsumingService' => [
      'serviceName' => 'geve|Online',
      'serviceDescription' => 'Authentifizierung an einem Online-Dienst',
      'version' => '2',
      'url' => '',
      'lang' => 'de',
      'authnMethods' => [
        'eID' => [
          'Enabled' => true,
          'Berechtigungszertifikat' => [
            'Bundesland' => 'BY',
          ]
        ],
        'FINK' => [
          'Enabled' => true,
        ],
      ],
      'requestedAttributes' => [
        ['name' => 'urn:oid:2.5.4.42', 'isRequired' => true, 'nameFormat' => '', 'friendlyName' => 'givenName', 'attributeValue' => [],],
        ['name' => 'urn:oid:2.5.4.4', 'isRequired' => true, 'nameFormat' => '', 'friendlyName' => 'surname', 'attributeValue' => [],],
        ['name' => 'urn:oid:0.9.2342.19200300.100.1.3', 'isRequired' => true, 'nameFormat' => '', 'friendlyName' => 'mail', 'attributeValue' => [],],
        ['name' => 'urn:oid:2.5.4.16', 'isRequired' => true, 'nameFormat' => '', 'friendlyName' => 'postalAddress', 'attributeValue' => [],],
        ['name' => 'urn:oid:2.5.4.17', 'isRequired' => true, 'nameFormat' => '', 'friendlyName' => 'postalCode', 'attributeValue' => [],],
        ['name' => 'urn:oid:2.5.4.7', 'isRequired' => true, 'nameFormat' => '', 'friendlyName' => 'localityName', 'attributeValue' => [],],
        ['name' => 'urn:oid:1.2.40.0.10.2.1.1.225599', 'isRequired' => true, 'nameFormat' => '', 'friendlyName' => 'country', 'attributeValue' => [],],
        ['name' => 'urn:oid:0.9.2342.19200300.100.1.40', 'isRequired' => false, 'nameFormat' => '', 'friendlyName' => 'personalTitle', 'attributeValue' => [],],
        ['name' => 'urn:oid:1.3.6.1.4.1.33592.1.3.5', 'isRequired' => true, 'nameFormat' => '', 'friendlyName' => 'gender', 'attributeValue' => [],],
        ['name' => 'urn:oid:1.2.40.0.10.2.1.1.55', 'isRequired' => true, 'nameFormat' => '', 'friendlyName' => 'birthdate', 'attributeValue' => [],],
        ['name' => 'urn:oid:1.3.6.1.5.5.7.9.2', 'isRequired' => true, 'nameFormat' => '', 'friendlyName' => 'placeOfBirth', 'attributeValue' => [],],
        ['name' => 'urn:oid:1.2.40.0.10.2.1.1.225566', 'isRequired' => false, 'nameFormat' => '', 'friendlyName' => 'birthName', 'attributeValue' => [],],
        ['name' => 'urn:oid:1.2.40.0.10.2.1.1.225577', 'isRequired' => true, 'nameFormat' => '', 'friendlyName' => 'nationality', 'attributeValue' => [],],
        ['name' => 'urn:oid: 1.2.40.0.10.2.1.1.552255', 'isRequired' => false, 'nameFormat' => '', 'friendlyName' => 'documentType', 'attributeValue' => [],],
        // ['name' => 'urn:oid:1.3.6.1.4.1.55605.70737875.1.1.1.7.1', 'isRequired' => true, 'nameFormat' => '', 'friendlyName' => 'DeMail', 'attributeValue' => [],],
        ['name' => 'urn:oid:2.5.4.20', 'isRequired' => true, 'nameFormat' => '', 'friendlyName' => 'telephoneNumber', 'attributeValue' => [],],
        // ['name' => 'urn:oid:1.3.6.1.4.1.25484.494450.10.1', 'isRequired' => false, 'nameFormat' => '', 'friendlyName' => 'eIDAS-Issuing-Country', 'attributeValue' => [],],
        // ['name' => 'urn:oid:1.3.6.1.4.1.25484.494450.5 ', 'isRequired' => true, 'nameFormat' => '', 'friendlyName' => 'communityId', 'attributeValue' => [],]
      ]
    ],
    'singleLogoutService' => [
      'url' => 'https://online.geve-services.de/saml/logout',
      'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    ],
    'x509cert' => '',
    'privateKey' => '',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
  ],
  'idp' => [
    'entityId' => 'https://int.id.bund.de/idp',
    'singleSignOnService' => [
      'url' => 'https://int.id.bund.de/idp/profile/SAML2/Redirect/SSO',
      'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    ],
    'singleLogoutService' => [
      'url' => 'https://int.id.bund.de/idp/profile/SAML2/Redirect/SLO',
      'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
      'responseUrl' => '',
    ],
    'x509cert' => '',
  ],
  'compress' => [
    'requests' => true,
    'responses' => true,
  ],
  'security' => [
    'nameIdEncrypted' => false,
    'authnRequestsSigned' => true,
    'logoutRequestSigned' => false,
    'logoutResponseSigned' => false,
    'signMetadata' => false,
    'wantMessagesSigned' => true,
    'wantAssertionsEncrypted' => false,
    'wantAssertionsSigned' => true,
    'wantNameId' => true,
    'wantNameIdEncrypted' => false,
    'requestedAuthnContext' => ['STORK-QAA-Level-3'],
    'requestedAuthnContextComparison' => 'minimum',
    'wantXMLValidation' => true,
    'relaxDestinationValidation' => false,
    'allowRepeatAttributeName' => false,
    'destinationStrictlyMatches' => false,
    'rejectUnsolicitedResponsesWithInResponseTo' => false,
    'signatureAlgorithm' => 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1',
    'digestAlgorithm' => 'http://www.w3.org/2001/04/xmlenc#sha256',
    'encryption_algorithm' => 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
    'lowercaseUrlencoding' => false,
  ],
  'debug' => true,
  'contactPerson' => [
    'technical' => [
      'givenName' => 'Tobias Runkel',
      'emailAddress' => 'runkel@edv-ermtraud.de',
    ],
    'support' => [
      'givenName' => 'Tobias Runkel',
      'emailAddress' => 'runkel@edv-ermtraud.de',
    ],
  ],
  'organization' => [
    'de-DE' => [
      'name' => 'EDV Ermtraud GmbH',
      'displayname' => 'geve|Online - ',
      'url' => 'https://www.edv-ermtraud.de',
    ],
  ],
];
