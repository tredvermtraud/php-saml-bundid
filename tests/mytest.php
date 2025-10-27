<?php

require_once implode(DIRECTORY_SEPARATOR, [__DIR__, "settings", "settings8.php"]);
require_once implode(DIRECTORY_SEPARATOR, [__DIR__, "bootstrap.php"]);

use Ermtraud\Saml2\AuthnRequest2;
use Ermtraud\Saml2\Settings;


$s = new Settings($settings, true);
$test = new AuthnRequest2($s);
$test->buildBundIDStruct();
echo $test->getXML();