<?php

//DEFINE("CAS_SERVER", "https://cas-prepro.cclearning.accenture.com"); //PREPRO
DEFINE("CAS_SERVER", "https://cas-server.cclearning.accenture.com"); //LOCAL
DEFINE("CAS_INSTANCE", "cas");
DEFINE("CAS_USER", "moodle");
DEFINE("CAS_PASS", "moodle");
DEFINE("CAS_TENANT", "accn");
DEFINE("MOODLE_HOST", "https://accn-moodle-prepro.cclearning.accenture.com");
DEFINE("PROXY_CALLBACK_PATH", "local/util/CasClientCCelearning");
DEFINE("PROXY_CALLBACK_FILE", "proxyCallback.php");
DEFINE("PROXY_TICKETS_FOLDER", "/proxy_tickets");

//CERTS DEFAULTS PATHS
DEFINE("SSL_CERT", $_SERVER['DOCUMENT_ROOT'] . '/local/util/certs/cert.cert');
DEFINE("SSL_KEY", $_SERVER['DOCUMENT_ROOT'] . '/local/util/certs/key.key');
DEFINE("CA_INFO", $_SERVER['DOCUMENT_ROOT'] . '/local/util/certs/chain.pem');
DEFINE("SSL_KEY_PASSWORD","cclearning");
?>
