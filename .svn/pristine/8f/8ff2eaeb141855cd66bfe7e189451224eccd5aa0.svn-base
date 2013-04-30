<?php

/*
 * PLAYERS
 * ------------------------------------
 * CAS: The Central Authentication Service.A trusted arbiter of authenticity.
 * Service: A web application that authenticates users via CAS.
 * Proxy: A service that wants to access other services on behalf of
 *        a particular user.
 * Target (or back-end service): A service that accepts proxied credentials from
 *                               at least one particular proxy.
 */
require_once('StatusCodes.php');

class CasClientCCelearning {

    /**
     *
     * @var string 
     */
    private $_restApi = "v1/tickets";
    private $_casServerUrl = "";
    private $_TGT = '';
    private $_ch;
    private $_casServer;
    private $_casInstance;
    public $proxyCallback = '';

    /**
     * The user of proxy ticket when its validate.
     * @var string 
     */
    private $_ptUser;
    public $error;

    public function __construct($casServer, $casInstance, $useProxy = false, $casPort = 443) {
        try {
            $this->_setCasServer($casServer);
            $this->_setUseProxy($useProxy);
            $this->_setCasInstance($casInstance);
            $this->_setCasPort($casPort);

            $this->_casServerUrl = implode("", array($this->_casServer, $this->_casInstance, $this->_restApi));
        } catch (Exception $exc) {
            self::_setError($exc->getCode(), $exc->getMessage(), __FUNCTION__);
        }

        $this->error = new stdclass();
        $this->error->code = "";
        $this->error->message = "";
    }

    /**
     * Set the cas port.
     * 
     * If the port is 0 or not is an integer a throws UnexpectedValueException. 
     * 
     * @param integer $casPort
     * @throws UnexpectedValueException
     */
    protected function _setCasPort($casPort) {
        if ($casPort == 0 || !is_int($casPort)) {
            throw new UnexpectedValueException(
                    'bad CAS server port (`' . $casPort . '\')'
            );
        }
        $this->_casPort = $casPort;
    }

    /**
     * Set cas server URL.
     * 
     * If the url is not valid throws InvalidArgumentException.
     * 
     * @param string $casServer
     * @throws InvalidArgumentException
     */
    protected function _setCasServer($casServer) {
        $url_scheme = parse_url($casServer, PHP_URL_SCHEME);
        if ($url_scheme <> 'https' || $this->_validURL($casServer) === false) {
            throw new InvalidArgumentException(
                    '$casServer must be a valid url (with the protocol https).
                    The value is: ' . $casServer
            );
        }
        $this->_casServer = $casServer;
    }

    protected function _setCasInstance($casInstance) {
        if (!preg_match('/[\.\d\-_abcdefghijklmnopqrstuvwxyz\/]*/', $casInstance)) {
            throw new InvalidArgumentException(
                    'Cas Instance must be a valid'
            );
        }
        $server_uri = preg_replace('/\/\//', '/', '/' . $casInstance . '/');
        $this->_casInstance = $server_uri;
    }

    protected function _setUseProxy($use_proxy) {
        /*
         * Returns true for "1", "true", "on" and "yes". Returns false otherwise.
         * If FILTER_null_ON_FAILURE is set, false is returned only for "0", "false", "off", "no", and "",
         * and null is returned for all non-boolean values.
         */

        if (($boolean = filter_var(var_export($use_proxy, true), FILTER_VALIDATE_BOOLEAN,FILTER_NULL_ON_FAILURE)) === null) {
            throw new InvalidArgumentException(
                    '$use_proxy must be true, "1", "true", "on" and "yes" or false, "0", "false", "off", "no", and "". The value is: ' . $use_proxy
            );
        } else if ($boolean === true) {
            $this->_useProxy = true;
        } else {
            $this->_useProxy = false;
        }
    }

    protected function _validURL($casServer) {
        if (filter_var($casServer, FILTER_VALIDATE_URL) === false) {
            return false;
        }
        return true;
    }

    /**
     * Init curl session
     * 
     * $params = array('url' => '',
     *                   'host' => '',
     *                   'header' => '',
     *                   'method' => '',
     *                   'referer' => '',
     *                   'cookie' => '',
     *                   'post_fields' => '',
     *                    ['login' => '',]
     *                    ['password' => '',]      
     *                   'timeout' => 0
     *                   'ssl_config' => array(), ----> TODO.
     *                   );
     */
    protected function _init($params) {
        $this->_ch = curl_init();

        //curl opciones comunes a todos los casos.
        $options = array(
            CURLOPT_URL => $params['url'],
            CURLOPT_HTTPHEADER => $params['header'],
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_VERBOSE => 1,
            CURLOPT_HEADER => 1,
        );

        @curl_setopt_array($this->_ch, $options);

        //SSL opciones y configuracion de certificados.
        //TODO: meterlo en una array de opciones y pasar los parametros de
        //configuracion desde la clase.
        @curl_setopt($this->_ch, CURLOPT_SSL_VERIFYPEER, 1);
        @curl_setopt($this->_ch, CURLOPT_SSL_VERIFYHOST, 1);
        @curl_setopt($this->_ch, CURLOPT_SSLVERSION, 3);
        @curl_setopt($this->_ch, CURLOPT_SSLCERT, $this->getSSLcert());
        @curl_setopt($this->_ch, CURLOPT_SSLCERTTYPE, 'PEM');
        @curl_setopt($this->_ch, CURLOPT_SSLKEY, $this->getSSLkey());
        @curl_setopt($this->_ch, CURLOPT_SSLKEYPASSWD, $this->_getCAinfo());
        @curl_setopt($this->_ch, CURLOPT_CAINFO, $this->getCAinfo());

        if ($params['method'] == "POST") {
            @curl_setopt($this->_ch, CURLOPT_POST, true);
            @curl_setopt($this->_ch, CURLOPT_POSTFIELDS, $params['post_fields']);
        }
    }

    /**
     * Make curl request
     *
     * @return array  'header','body','curl_error','http_code','last_url'
     */
    protected function _exec() {
        $response = curl_exec($this->_ch);
        $error = curl_error($this->_ch);
        $result = array(
            'header' => '',
            'body' => '',
            'curl_error' => '',
            'http_code' => ''
        );
        if ($error != "") {
            $result['curl_error'] = $error;
            return $result;
        }

        $header_size = curl_getinfo($this->_ch, CURLINFO_HEADER_SIZE);
        $result['header'] = substr($response, 0, $header_size);
        $result['body'] = substr($response, $header_size);
        $result['http_code'] = curl_getinfo($this->_ch, CURLINFO_HTTP_CODE);

        curl_close($this->_ch);

        return $result;
    }

    public function getCurrentURL() {
        $pageURL = 'http';
        if (isset($_SERVER["HTTPS"])) {
            if ($_SERVER["HTTPS"] == "on") {
                $pageURL .= "s";
            }
        }
        $pageURL .= "://";
        if ($_SERVER["SERVER_PORT"] != "80") {
            $pageURL .= $_SERVER["SERVER_NAME"]; // . ":" . $_SERVER["SERVER_PORT"] . $_SERVER["REQUEST_URI"];
        } else {
            $pageURL .= $_SERVER["SERVER_NAME"]; //. $_SERVER["REQUEST_URI"];
        }
        return $pageURL;
    }

    /*
     * Metodos generales de la clase
     */

    /**
     * Request for a Ticket Granting Ticket.
     * 
     * Set the variable TGT in the class object.
     * To obtain the value , execute the method getTGT() after the execution 
     * of this method.
     * 
     * @link https://wiki.jasig.org/display/CASUM/RESTful+API REST API Doc.
     * 
     * @param string $username
     * @param string $password 
     * @param string $tenant
     * 
     * @return boolean true en caso de exito o FAlSE en caso de error.
     * */
    public function requestTGT($username, $password, $tenant) {
        ini_set('arg_separator.output', '&');
        $post_params = http_build_query(
                array(
                    "username" => $username,
                    "password" => $password,
                    "tenant" => $tenant
                ));
        try {
            $params = array(
                'url' => $this->_casServerUrl,
                'header' => array(
                    "Content-type: application/x-www-form-urlencoded",
                    'Accept: text/plain'
                ),
                'method' => 'POST',
                'post_fields' => $post_params,
            );

            $this->_init($params);
            $result = $this->_exec();

            if ($result['curl_error']) {
                $code = "CURL_EXEC_FAILED";
                $message = $result['curl_error'];
                self::_setError($code, $message, __FUNCTION__);
            } else {
                $statusCode = new StatusCodes();
                if ($result['http_code'] === $statusCode::HTTP_CREATED) {
                    $header_as_array = $this->_get_headers_from_curl_response($result['header']);
                    if (array_key_exists('Location', $header_as_array)) {
                        $location = $header_as_array['Location'];
                        $tgt_pos = strrpos($location, "/");
                        $TGT = substr($location, $tgt_pos + 1);
                        $this->_setTGT($TGT);
                        return true;
                    } else {
                        $code = "TICKET_NOT_FOUND";
                        $httpCode = $result['http_code'];
                        $hedaerResponse = $result['header'];
                        $message = sprintf("The response from cas server was susscesfull
                                but \"Location:\" header not found.\r\n
                                Code: %s \r\n
                                Header: %s\r\n
                                ", $httpCode, $hedaerResponse);
                        self::_setError($code, $message, __FUNCTION__);
                    }
                } else {
                    $httpCode = $result['http_code'];
                    $responseHtml = $result['body'];
                    if ($statusCode->isError($result['http_code'])) {
                        $httpCode = $statusCode->getMessageForCode($result['http_code']);
                        if ($statusCode->canHaveBody($result['http_code'])) {
                            $responseBody = self::_getBodyText($responseHtml);
                        }
                    }
                    $code = "BAD_RESPONSE_CAS_SERVER";
                    $message = sprintf("Unexpected response from CAS server. 
                        The HTTP code response was \"%s\" 
                        and the message: \"%s\"", $httpCode, $responseBody);
                    self::_setError($code, $message, __FUNCTION__);
                }
            }
        } catch (Exception $e) {
            //Unexpected exception...
            self::_setError($e->getCode(), $e->getMessage());
            return false;
        }

        //Si llegamos a este punto es que no se ha obtenido el TGT, por lo que
        //se ha producido algun error. Se puede consultar el metodo
        //getLastError() para saber porque ha fallado.
        return false;
    }

    /**
     * Request for a Service Ticket (ST).
     * 
     * A ticket sent by CAS, through the user's browser, to a service. 
     * Each ST may be used only once, and must be combined with the unique 
     * identifier for one specific service in order to be useful. (Put another way, 
     * a service that knows its own unique identifier will refuse to accept STs 
     * intended for another service. This prevents one service from mounting a 
     * "man in the middle" attack against another.)
     * 
     * @link https://wiki.jasig.org/display/CASUM/RESTful+API
     * 
     * @param type $service
     * @param type $tenant
     * @param type $TGT
     * @return boolean
     */
    public function requestST($service, $tenant, $TGT) {

        if (!empty($TGT) && !empty($tenant)) {
            $this->_casServerUrl = implode("/", array($this->_casServerUrl, $TGT));

            $post_params = http_build_query(
                    array(
                        "service" => $service,
                        "tenant" => $tenant
                    ));

            $params = array(
                'url' => $this->_casServerUrl,
                'header' => array(
                    "Content-type: application/x-www-form-urlencoded",
                    'Accept: text/plain'
                ),
                'method' => 'POST',
                'post_fields' => $post_params,
            );

            try {
                $this->_init($params);
                $result = $this->_exec();
                $statusCode = new StatusCodes();
                if ($result['curl_error']) {
                    $code = "CURL_EXEC_FAILED";
                    $message = $result['curl_error'];
                    self::_setError($code, $message, __FUNCTION__);
                } else {
                    if ($result['http_code'] == $statusCode::HTTP_OK) {
                        if ($result['body'] <> '') {
                            $ticket = $result['body'];
                            if (!preg_match('/^[S]T-/', $ticket)) {
                                $code = "UNEXPECTED_RESPONSE_VALUE";
                                $message = sprintf("ST format invalid: %s", $ticket);
                                self::_setError($code, $message, __FUNCTION__);
                                return false;
                            }
                            $this->_setST($ticket);
                            unset($_GET['ticket']);
                            return true;
                        } else {
                            $code = "TGT_TICKET_NOT_FOUND";
                            $httpCode = $result['http_code'];
                            $bodyResponse = $result['body'];
                            $message = sprintf("The response from cas server was susscesfull
                                but ST ticket not found in the body response.\r\n
                                Code: %s \r\n
                                Body: %s\r\n
                                ", $httpCode, $bodyResponse);
                            self::_setError($code, $message, __FUNCTION__);
                        }
                    } else {
                        $httpCode = $result['http_code'];
                        $responseHtml = $result['body'];
                        if ($statusCode->isError($result['http_code'])) {
                            $httpCode = $statusCode->getMessageForCode($result['http_code']);
                            if ($statusCode->canHaveBody($result['http_code'])) {
                                $responseBody = self::_getBodyText($responseHtml);
                            }
                        }

                        $code = "BAD_RESPONSE_CAS_SERVER";
                        $message = sprintf("Unexpected response from CAS server. 
                        The HTTP code response was \"%s\" 
                        and the message: \"%s\"", $httpCode, $responseBody);

                        self::_setError($code, $message, __FUNCTION__);
                    }
                }
            } catch (Exception $e) {
                //unexpected exception...
                self::_setError($e->getCode(), $e->getMessage(), __FUNCTION__);
                return false;
            }
        } else {
            $code = "WRONG_PARAMETERS";
            $message = "Some parameters are empty. 
                All parameters must contain a correct value.";
            self::_setError($code, $message, __FUNCTION__);
        }

        return false; //Some error found...
    }

    /**
     * Validate Service Ticket
     * 
     * The serviceValidate checks the validity of a service ticket.
     * 
     * Usar getCurrentURL() para obtener la url del servicio...
     * 
     * @link http://www.jasig.org/cas/protocol
     * 
     * @param string $service The identifier of the service for which the ticket was issued
     * @param string $ticket The service ticket
     * @param bool $proxy
     * @return boolean
     */
    public function serviceValidate($service, $ticket, $pgtUrl = "", $useProxy = false) {

        if (!(empty($ticket)) && preg_match('/^[S]T-/', $ticket) && self::_validURL($service)) {
            $url_basic = implode("", array($this->_casServer, $this->_casInstance, "serviceValidate"));

            $basic_params = array(
                "service" => $service,
                "ticket" => $ticket
            );

            if ($useProxy) {
                $basic_params['pgtUrl'] = $pgtUrl;
            }

            $url_params = http_build_query($basic_params);

            $url = implode("?", array($url_basic, $url_params));

            $params = array(
                'url' => $url,
                'header' => array(
                    "Content-type: application/x-www-form-urlencoded",
                    'Accept: text/plain'
                ),
                'method' => 'GET',
            );

            try {
                $this->_init($params);
                $result = $this->_exec();
                $statusCode = new StatusCodes();

                if ($result['curl_error']) {
                    $code = "CURL_EXEC_FAILED";
                    $message = $result['curl_error'];
                    self::_setError($code, $message, __FUNCTION__);
                } else {
                    if ($result['http_code'] === $statusCode::HTTP_OK) {
                        $xmlDoc = new DOMDocument();
                        $xmlDoc->preserveWhiteSpace = false;
                        $xmlDoc->encoding = "utf-8";
                        if ($xmlDoc->loadXML($result['body'])) {
                            $x = $xmlDoc->documentElement;
                            if ($x->tagName == 'cas:serviceResponse') {
                                $node = $x->firstChild;
                                switch ($node->nodeName) {
                                    case 'cas:authenticationSuccess':
                                        //Esperamos que sea el nombre del usuario...
                                        $user_domElement = $node->firstChild;
                                        if (!empty($user_domElement) &&
                                                ($user_domElement->nodeName == 'cas:user')) {
                                            $user = $user_domElement->nodeValue;
                                            $this->_setUser($user);
                                        } else {
                                            $code = "UNEXPECTED_RESPONSE_VALUE";
                                            $body = $result['body'];
                                            $message = sprintf("Unknown xml format. The tag '<cas:user>' was not found.
                                                        The response body was the following: %s", $body);
                                            self::_setError($code, $message, __FUNCTION__);
                                            break;
                                        }
                                        //si tenemos el proxy habilitado...
                                        if ($useProxy) {
                                            $pgtiou_domElement = $user_domElement->nextSibling;
                                            if (!empty($pgtiou_domElement) && ($pgtiou_domElement->nodeName == 'cas:proxyGrantingTicket')) {
                                                $pgtiou = $pgtiou_domElement->nodeValue;
                                                if (preg_match('/PGTIOU-[\.\-\w]/', $pgtiou)) {
                                                    $this->_setPGTIOU($pgtiou);
                                                    return true;
                                                } else {
                                                    $code = "UNEXPECTED_RESPONSE_VALUE";
                                                    $body = $result['body'];
                                                    $message = sprintf("PGTiou format invalid: %s", $pgtiou);
                                                    self::_setError($code, $message, __FUNCTION__);
                                                    break;
                                                }
                                            } else {
                                                $code = "UNEXPECTED_RESPONSE_VALUE";
                                                $body = $result['body'];
                                                $message = sprintf("Unknown xml format. The tag '<cas:proxyGrantingTicket>' was not found.
                                                        The response body was the following: %s", $body);
                                                self::_setError($code, $message, __FUNCTION__);
                                                break;
                                            }
                                        } else {
                                            //User already validate and proxy is not necesarry to evaluate...
                                            return true;
                                        }
                                        break;
                                    case 'cas:authenticationFailure':
                                        /*
                                         * INVALID_REQUEST - not all of the required request parameters were present
                                         * INVALID_TICKET - the ticket provided was not valid, or the ticket did not come from an initial login and "renew" was set on validation. The body of the <cas:authenticationFailure> block of the XML response SHOULD describe the exact details.
                                         * INVALID_SERVICE - the ticket provided was valid, but the service specified did not match the service associated with the ticket. CAS MUST invalidate the ticket and disallow future validation of that same ticket.
                                         * INTERNAL_ERROR - an internal error occurred during ticket validation
                                         */
                                        $code = $node->getAttribute('code');
                                        $message = $node->nodeValue;
                                        self::_setError($code, $message, __FUNCTION__);
                                        break;
                                    default:
                                        $code = "UNEXPECTED_RESPONSE_VALUE";
                                        $body = $result['body'];
                                        $message = sprint("Unknown xml format. Neither '<proxySuccess>' nor '<proxyFailure>' found.
                                                    The response body was the following: %s", $body);
                                        self::_setError($code, $message, __FUNCTION__);
                                        break;
                                }
                            } else {
                                $code = "UNEXPECTED_RESPONSE_VALUE";
                                $body = $result['body'];
                                $message = sprint("Unknown xml format.The main tag '<cas:serviceResponse>' was not found.
                                            The response body was the following: %s", $body);
                                self::_setError($code, $message, __FUNCTION__);
                            }
                        } else {
                            throw new Exception('dom->loadXML() failed');
                        }
                    } else {
                        $httpCode = $result['http_code'];
                        $responseHtml = $result['body'];
                        if ($statusCode->isError($result['http_code'])) {
                            $httpCode = $statusCode->getMessageForCode($result['http_code']);
                            if ($statusCode->canHaveBody($result['http_code'])) {
                                $responseBody = self::_getBodyText($responseHtml);
                            }
                        }

                        $code = "BAD_RESPONSE_CAS_SERVER";
                        $message = sprintf("Unexpected response from CAS server. 
                        The HTTP code response was \"%s\" 
                        and the message: \"%s\"", $httpCode, $responseBody);

                        self::_setError($code, $message, __FUNCTION__);
                    }
                }
            } catch (Exception $e) {
                //unexpected exception...
                self::_setError($e->getCode(), $e->getMessage(), __FUNCTION__);
                return false;
            }
        } else {

            //todo sacar detalle de que parametros provoca el error...
            $code = "WRONG_PARAMETERS";
            $message = "The ticket param is empty or contain an invalid value. 
                A service ticket(ST) must start with \"ST-\".";
            self::_setError($code, $message, __FUNCTION__);
        }

        //Si llegamos a este punto es que no se ha validado el ticket.
        //Consultar el ultimo error con _getLastError().
        return false;
    }

    /**
     * Proxy-granting ticket (PGT)
     * 	
     * A ticket sent by CAS to a service holding a valid ST (but see below). 
     * This ticket (associated with an individual service and an individual user) 
     * confers the ability to produce proxy tickets.
     * 
     * @param type $pgtiou Proxy-granting ticket IOU (PGTIOU): A ticket sent by CAS 
     * alone in a service validation response, and with a PGT 
     * to the callback URL. It is the web application's responsibility to maintain 
     * a table to correlate PGTIOUs and PGTs
     * 
     * @return boolean
     */
    public function requestPGT($pgtiou, $server, $path) {
        try {
            $url = implode("/", array($server, $path));
            $file = implode(".", array($pgtiou, "txt"));
            $fullPath = implode("/", array($url, $file));
            $PGT = file_get_contents($fullPath);
            if (preg_match('/[PT]GT-[\.\-\w]/', $PGT)) {
                $this->_setPGT($PGT);
                return true;
            } else {
                $code = "PGT_TICKET_NOT_FOUND";
                $message = sprintf("PGT ticket format incorrect: \"%s\"", $PGT);
                self::_setError($code, $message, __FUNCTION__);
            }
        } catch (Exception $exc) {
            self::_setError($exc->getCode(), $exc->getMessage(), __FUNCTION__);
            return false;
        }

        return false;
    }

    /**
     * Provides proxy tickets to services that have acquired proxy-granting 
     * tickets and will be proxying authentication to back-end services
     * 
     * @param type $pgt  The proxy-granting ticket acquired by the service 
     *                   during service ticket or proxy ticket validation.
     * @param type $targetService The service identifier of the back-end service. 
     *                            Note that not all back-end services are web 
     *                            services so this service identifier will not 
     *                            always be a URL. However, the service identifier 
     *                            specified here MUST match the "service" parameter 
     *                            specified to /proxyValidate upon validation of 
     *                            the proxy ticket.
     * @return boolean True on suscess false on failure.
     * @throws Exception If dom->loadXML() failed.
     */
    public function requestPT($pgt, $targetService) {
        if (preg_match('/[PT]GT-[\.\-\w]/', $pgt)) {
            $url_basic = implode("", array($this->_casServer, $this->_casInstance, "proxy"));
            $url_params = http_build_query(
                    array(
                        "targetService" => $targetService,
                        "pgt" => $pgt
                    ));

            $url = implode("?", array($url_basic, $url_params));

            $params = array(
                'url' => $url,
                'header' => array(
                    "Content-type: application/x-www-form-urlencoded",
                    'Accept: text/plain'
                ),
                'method' => 'GET',
            );

            try {
                $this->_init($params);
                $result = $this->_exec();
                $statusCode = new StatusCodes();
                if ($result['curl_error']) {
                    $code = "CURL_EXEC_FAILED";
                    $message = $result['curl_error'];
                    self::_setError($code, $message, __FUNCTION__);
                } else {
                    if ($result['http_code'] === $statusCode::HTTP_OK) {
                        $xmlDoc = new DOMDocument();
                        $xmlDoc->preserveWhiteSpace = false;
                        $xmlDoc->encoding = "utf-8";
                        if ($xmlDoc->loadXML($result['body'])) {
                            $x = $xmlDoc->documentElement;
                            if ($x->tagName == 'cas:serviceResponse') {
                                $node = $x->firstChild;
                                switch ($node->nodeName) {
                                    //On request success...
                                    case 'cas:proxySuccess':
                                        $PT_domElement = $node->firstChild;
                                        if (!empty($PT_domElement) &&
                                                ($PT_domElement->nodeName == 'cas:proxyTicket')) {
                                            $PT = $PT_domElement->nodeValue;
                                            if (preg_match('/^[SP]T-/', $PT)) {
                                                $this->_setPT($PT);
                                                return true;
                                            } else {
                                                $code = "UNEXPECTED_RESPONSE_VALUE";
                                                $message = "The tag <cas:proxyTicket> was found in the response but the ticket is malformed.
                                                            The respose body was the following: "
                                                        . $result['body'];
                                                self::error($code, $message);
                                                return false;
                                            }
                                        } else {
                                            $code = "UNEXPECTED_RESPONSE_VALUE";
                                            $message = "Unkown xml format. <cas:proxySuccess> tag was found, but not <cas:proxyTicket> tag. 
                                                        The response body was the following: "
                                                    . $result['body'];
                                            self::error($code, $message);
                                            return false;
                                        }
                                        break;
                                    //On request failure...    
                                    case 'cas:proxyFailure':
                                        /*
                                         * INVALID_REQUEST - not all of the required request parameters were present
                                         * BAD_PGT - the pgt provided was invalid
                                         * INTERNAL_ERROR - an internal error occurred during ticket validation
                                         */
                                        $code = $node->getAttribute('code');
                                        $message = $node->nodeValue;
                                        self::_setError($code, $message, __FUNCTION__);
                                        break;
                                    //Unexpected response...
                                    default:
                                        $code = "UNEXPECTED_RESPONSE_VALUE";
                                        $body = $result['body'];
                                        $message = sprint("Unknown xml format. Neither '<proxySuccess>' nor '<proxyFailure>' found.
                                                    The response body was the following: %s", $body);
                                        self::_setError($code, $message, __FUNCTION__);

                                        break;
                                }
                            } else {
                                $code = "UNEXPECTED_RESPONSE_VALUE";
                                $body = $result['body'];
                                $message = sprint("Unknown xml format.The main tag '<cas:serviceResponse>' was not found.
                                            The response body was the following: %s", $body);
                                self::_setError($code, $message, __FUNCTION__);
                            }
                        } else {
                            throw new Exception('dom->loadXML() failed');
                        }
                    } else {
                        $httpCode = $result['http_code'];
                        $responseHtml = $result['body'];
                        if ($statusCode->isError($result['http_code'])) {
                            $httpCode = $statusCode->getMessageForCode($result['http_code']);
                            if ($statusCode->canHaveBody($result['http_code'])) {
                                $responseBody = self::_getBodyText($responseHtml);
                            }
                        }

                        $code = "BAD_RESPONSE_CAS_SERVER";
                        $message = sprintf("Unexpected response from CAS server. 
                        The HTTP code response was \"%s\" 
                        and the message: \"%s\"", $httpCode, $responseBody);

                        self::_setError($code, $message, __FUNCTION__);
                    }
                }
            } catch (Exception $exc) {
                //unexpected exception...
                self::_setError($exc->getCode(), $exc->getMessage(), __FUNCTION__);
                return false;
            }
        } else {
            $code = "PGT_TICKET_INVALID";
            $message = "PGT ticket format is invalid. The ticket provieded is: " . $pgt;
            self::_setError($code, $message, __FUNCTION__);
        }
        return false;
    }

    /**
     * Proceso completo para solicitar un PT, TGT->ST->PGT.
     * 
     * @param type $pgt
     * @param type $targetService
     * @return boolean
     * @throws Exception
     */
    public function requestPT_full_process($proxyTicketParams) {

        $username = $proxyTicketParams['tgtParams']['username'];
        $password = $proxyTicketParams['tgtParams']['password'];
        $tenant = $proxyTicketParams['tgtParams']['tenant'];

        $service = $proxyTicketParams['service'];
        $targetService = $proxyTicketParams['targetService'];
        $this->setSSLcert($proxyTicketParams['certs']['sslCertPath']);
        $this->setSSLkey($proxyTicketParams['certs']['sslKeyPath']);
        $this->setCAinfo($proxyTicketParams['certs']['CAinfoPath']);
        $this->setSSLkeypasswd($proxyTicketParams['certs']['SSLkeypasswd']);

        if ($this->requestTGT($username, $password, $tenant)) {
            $TGT = $this->getTGT();
            if ($this->requestST($service, $tenant, $TGT)) {
                $ticket = $this->getST();
                //3º Paso Validar ST.
                //$service -> UTILIZAMOS EL SERVICE DEL PASO 2...
                //$ticket --> EL OBTENIDO EN EL PASO 2.
                $pgtUrl = implode("/", array($service, PROXY_CALLBACK_PATH, PROXY_CALLBACK_FILE));
                $useProxy = true;
                if ($this->serviceValidate($service, $ticket, $pgtUrl, $useProxy)) {
                    $pgtiou = $this->getPGTIOU();
                    //4º Paso, Obtener PGT...
                    $path = PROXY_CALLBACK_PATH . PROXY_TICKETS_FOLDER;
                    if ($this->requestPGT($pgtiou, $service, $path)) {
                        $pgt = $this->getPGT();
                        if ($this->requestPT($pgt, $targetService)) {
                            $ticket = $this->getPT();
                            return $ticket;
                        }
                    }
                }
            }
        }
        //Si llegamos aqui es que algun error ocurrio...
        return false;
    }

    /**
     * proxyValidate MUST perform the same validation tasks as serviceValidate
     * and additionally validate proxy tickets.
     *  
     * If $ticket is not pass as an argument the method will use the default PT of 
     * the class instance.
     * 
     * If return value is false is possible get the last error using the method
     * getLastError().
     * 
     * @link http://www.jasig.org/cas/protocol
     * @param string $service the identifier of the service for which the ticket was issued
     * @param string $_PT The proxy ticket. It possible pass a PT.
     * 
     * @return boolean true if the autheticantion was succes. false if not.
     */
    public function proxyValidate($service, $ticket = null) {

        //Podemos validar el PT de la propia clase o pasar uno por parametro,
        //por ejemplo, un ST que nos llegue desde un webservice.

        if (!(empty($ticket)) &&
                (preg_match('/^[SP]T-/', $ticket))) {
            $url_basic = implode("", array($this->_casServer, $this->_casInstance, "proxyValidate"));
            $url_params = http_build_query(
                    array(
                        "service" => $service,
                        "ticket" => $ticket,
                    ));

            $url = implode("?", array($url_basic, $url_params));

            $params = array(
                'url' => $url,
                'header' => array(
                    "Content-type: application/x-www-form-urlencoded",
                    'Accept: text/plain'
                ),
                'method' => 'GET',
            );

            try {
                $this->_init($params);
                $result = $this->_exec();
                $statusCode = new StatusCodes();
                if (!empty($result['curl_error'])) {
                    $code = "CURL_EXEC_ERROR";
                    $msg = $result['curl_error'];
                    $this->_setError($code, $msg, __FUNCTION__);
                } else {
                    if ($result['http_code'] === $statusCode::HTTP_OK) {
                        $xmlDoc = new DOMDocument();
                        $xmlDoc->preserveWhiteSpace = false;
                        $xmlDoc->encoding = "utf-8";
                        if ($xmlDoc->loadXML($result['body'])) {
                            $x = $xmlDoc->documentElement;
                            if ($x->tagName == 'cas:serviceResponse') {
                                $node = $x->firstChild;
                                switch ($node->nodeName) {
                                    case 'cas:authenticationSuccess':
                                        //Esperamos que sea el nombre del usuario...
                                        $user_domElement = $node->firstChild;
                                        if (!empty($user_domElement) &&
                                                ($user_domElement->nodeName == 'cas:user')) {
                                            $user = $user_domElement->nodeValue;
                                            $this->_setPtUser($user);
                                        } else {
                                            $code = "PT_USER_NOT_FOUND";
                                            $message = "La etiqueta <cas:user> no ha sido encontrada en la respuesta
                                            de CAS. El contenido de la respuesta es el siguiente: "
                                                    . $result['body'];
                                            self::error($code, $message);
                                            return false;
                                        }

                                        $proxies_domElement = $user_domElement->nextSibling;
                                        if (!empty($proxies_domElement) &&
                                                ($proxies_domElement->nodeName == 'cas:proxies')) {
                                            $proxies_DOMNodeList = $proxies_domElement->childNodes;
                                            if ($proxies_DOMNodeList->length <> 0) {
                                                for ($i = 0; $i < $proxies_DOMNodeList->length; $i++) {
                                                    $proxie_DomElement = $proxies_DOMNodeList->item($i);
                                                    if ($proxie_DomElement->nodeName == 'cas:proxy') {
                                                        $proxies[] = $proxie_DomElement->nodeValue;
                                                    }
                                                    $this->_setProxies($proxies);
                                                }
                                            } else {
                                                //TODO: no hay proxies en la lista..
                                                return false;
                                            }
                                        } else {
                                            //TODO: no hay etiqueta de proxy
                                        }

                                        return true;

                                        break;
                                    case 'cas:authenticationFailure':
                                        /*
                                         * INVALID_REQUEST - not all of the required request parameters were present
                                         * INVALID_TICKET - the ticket provided was not valid, or the ticket did not come from an initial login and "renew" was set on validation. The body of the <cas:authenticationFailure> block of the XML response SHOULD describe the exact details.
                                         * INVALID_SERVICE - the ticket provided was valid, but the service specified did not match the service associated with the ticket. CAS MUST invalidate the ticket and disallow future validation of that same ticket.
                                         * INTERNAL_ERROR - an internal error occurred during ticket validation
                                         */
                                        $code = $node->getAttribute('code');
                                        $msg = $node->nodeValue;
                                        $this->_setError($code, $msg, __FUNCTION__);
                                        break;
                                    default:
                                        $code = "UNEXPECTED_RESPONSE_VALUE";
                                        $body = $result['body'];
                                        $message = sprint("Unknown xml format. Neither '<cas:authenticationSuccess>' nor '<cas:authenticationFailure>' found.
                                                    The response body was the following: %s", $body);
                                        self::_setError($code, $message, __FUNCTION__);

                                        break;
                                        break;
                                }
                            } else {
                                $code = "UNEXPECTED_RESPONSE_VALUE";
                                $body = $result['body'];
                                $message = sprint("Unknown xml format.The main tag '<cas:serviceResponse>' was not found.
                                            The response body was the following: %s", $body);
                                self::_setError($code, $message, __FUNCTION__);
                            }
                        }
                    } else {
                        $httpCode = $result['http_code'];
                        $responseHtml = $result['body'];
                        if ($statusCode->isError($result['http_code'])) {
                            $httpCode = $statusCode->getMessageForCode($result['http_code']);
                            if ($statusCode->canHaveBody($result['http_code'])) {
                                $responseBody = self::_getBodyText($responseHtml);
                            }
                        }

                        $code = "BAD_RESPONSE_CAS_SERVER";
                        $message = sprintf("Unexpected response from CAS server. 
                        The HTTP code response was \"%s\" 
                        and the message: \"%s\"", $httpCode, $responseBody);

                        self::_setError($code, $message, __FUNCTION__);
                    }
                }
            } catch (Exception $e) {
                //unexpected exception...
                self::_setError($e->getCode(), $e->getMessage() . 'jhgff', __FUNCTION__);
                return false;
            }
        } else {
            //INVALID_PT
            //The proxy ticket is empty or mal former. The ticket is: . $ticket;
            $code = "PT_NOT_FOUND_OR_INVALID";
            $msg = "The proxy ticket(PT) is empty or malformed. The PT is: " . $ticket;
            $this->_setError($code, $msg, __FUNCTION__);
        }

        return false;
    }

    //##########################################################################
    // M�todos auxiliares de la clase
    //##########################################################################

    /**
     * Set the proxy callback URL. If the URL provided is not valid or not use
     * the https protocol an exception (InvalidArgumentException) will be
     * throw.
     * 
     * Return true if the URL has been set. Or false if not.
     * 
     * @param string $urlProxyCallback
     * @return boolean
     * @throws InvalidArgumentException
     */
    public function setProxyCallback($urlProxyCallback) {
        try {
            $url_scheme = parse_url($urlProxyCallback, PHP_URL_SCHEME);
            if ($url_scheme <> 'https' || $this->_validURL($urlProxyCallback) === false) {
                throw new InvalidArgumentException(
                        '$urlProxyCallback must be a valid url (with the protocol https).
                        The value is: ' . $urlProxyCallback
                );
            }
            $this->proxyCallback = $urlProxyCallback;
            return true;
        } catch (Exception $exc) {
            error_log($exc->getMessage());
            return false;
        }
    }

    public function getTenant() {
        $currentMoodle = $this->getCurrentURL();
        $url_parts = parse_url($currentMoodle);
        $delimiter = "-";
        $tenant = current(explode($delimiter, $url_parts['host']));
        return $tenant;
    }

    /**
     * 
     * @return null
     */
    public function getProxyCallback() {
        if ($this->hasProxyCallback()) {
            return $this->proxyCallback;
        } else {
            return false;
        }
    }

    public function hasProxyCallback() {
        if (!empty($this->proxyCallback)) {
            return true;
        }
        return false;
    }

    //TGT - Get, Set, Has methods...

    /**
     * Check if CAS object has TGT ticket.
     * 
     * @return boolean Return true if TGT has been. If not return false.
     */
    private function _hasTGT() {
        return !empty($this->_TGT);
    }

    /**
     * Set the TGT (ticket granted ticket).
     * 
     * @param $TGT The ticket granted ticket.
     * @private
     */
    private function _setTGT($TGT) {
        $this->_TGT = $TGT;
    }

    /**
     * This method get the TGT if has been set.
     * 
     * @return string
     */
    public function getTGT() {
        if ($this->_hasTGT()) {
            return $this->_TGT;
        }
    }

    //ST - Service Ticket has,get, set...

    /**
     * This method tells if a Service Ticket was stored.
     * @return true if a Service Ticket has been stored.
     * @private
     */
    private function hasST() {
        return !empty($this->ST);
    }

    /**
     * Set the service ticket (ST).
     * 
     * A ticket sent by CAS, through the user's browser, to a service. 
     * Each ST may be used only once, and must be combined with the unique 
     * identifier for one specific service in order to be useful. (Put another way, 
     * a service that knows its own unique identifier will refuse to accept STs 
     * intended for another service. This prevents one service from mounting a 
     * "man in the middle" attack against another.)
     * 
     * @param string $ST The Service Ticket.
     */
    private function _setST($ST) {
        $this->ST = $ST;
    }

    /**
     * This method get the Service Ticket if has been set.
     * @param $_st The Service Ticket.
     * @private
     * @return string or null if ST is empty.
     */
    public function getST() {
        if ($this->hasST()) {
            return $this->ST;
        } else {
            return null;
        }
    }

    //PGTIOU - Service Ticket has,get, set...

    /**
     * This method tells if a Service Ticket was stored.
     * @return true if a Service Ticket has been stored.
     * @private
     */
    private function hasPGTIOU() {
        return !empty($this->PGTIOU);
    }

    /**
     * This method stores the Service Ticket.
     * @param $_st The Service Ticket.
     * @private
     */
    private function _setPGTIOU($_pgtiou) {
        $this->PGTIOU = $_pgtiou;
    }

    /**
     * This method get the Service Ticket if has been set.
     * @param $_st The Service Ticket.
     * @private
     * @return string or null if ST is empty.
     */
    public function getPGTIOU() {
        if ($this->hasPGTIOU()) {
            return $this->PGTIOU;
        } else {
            return null;
        }
    }

    //PGTIOU - Service Ticket has,get, set...

    /**
     * This method tells if a Service Ticket was stored.
     * @return true if a Service Ticket has been stored.
     * @private
     */
    private function _hasPGT() {
        return !empty($this->PGT);
    }

    /**
     * This method stores the Service Ticket.
     * @param $_st The Service Ticket.
     * @private
     */
    private function _setPGT($_pgt) {
        $this->PGT = $_pgt;
    }

    /**
     * This method get the Service Ticket.
     * @param $_st The Service Ticket.
     * @private
     * @return string or null if ST is empty.
     */
    public function getPGT() {
        if ($this->_hasPGT()) {
            return $this->PGT;
        } else {
            return null;
        }
    }

    //PT - Service Ticket has,get, set...

    /**
     * This method tells if a Service Ticket was stored.
     * @return true if a Service Ticket has been stored.
     * @private
     */
    private function hasPT() {
        return !empty($this->PT);
    }

    /**
     * This method stores the Service Ticket.
     * @param $_st The Service Ticket.
     * @private
     */
    private function _setPT($_PT) {
        $this->PT = $_PT;
    }

    /**
     * This method get the Proxy Ticket if has been set.
     * 
     * @return string or null if PT is empty.
     */
    public function getPT() {
        if ($this->hasPT()) {
            return $this->PT;
        } else {
            return null;
        }
    }

    /*
     * Metodos auxiliares de los certificados...
     */

    /**
     * Set SSL certificate path.
     *  
     * @param string $sslCert The SSL cert file path.
     * @return boolean Return true if the file exists and is set. Return false if file not exists.
     */
    public function setSSLcert($sslCert) {
        if (file_exists($sslCert)) {
            $this->sslCert = $sslCert;
            return true;
        }
        return false;
    }

    private function hasSSLcert() {
        return !empty($this->sslCert);
    }

    /**
     * Get the SSL certificate path.
     * @return string
     */
    private function getSSLcert() {
        if ($this->hasSSLcert()) {
            return $this->sslCert;
        }
    }

    private function _setPtUser($user) {
        $this->_ptUser = $user;
    }

    public function getPtUser() {
        if ($this->hasPtUser()) {
            return $this->_ptUser;
        }
        return null;
    }

    public function hasPtUser() {
        return !empty($this->_ptUser);
    }

    /**
     * Set the SSL key path.
     * 
     * @param string $sslKey
     * @return boolean
     */
    public function setSSLkey($sslKey) {
        if (file_exists($sslKey)) {
            $this->sslKey = $sslKey;
            return true;
        }
        return false;
    }

    private function hasSSLkey() {
        return !empty($this->sslKey);
    }

    private function getSSLkey() {
        if ($this->hasSSLkey()) {
            return $this->sslKey;
        } else {
            return null;
        }
    }

    /**
     * Set the CA info path.
     *
     * @param string $CAinfo
     * @return boolean
     */
    public function setCAinfo($CAinfo) {
        if (file_exists($CAinfo)) {
            $this->cainfo = $CAinfo;
            return true;
        }
        return false;
    }

    /**
     * If CA info has been set return true. If not false.
     * 
     * @return boolean
     */
    private function hasCAinfo() {
        return !empty($this->cainfo);
    }

    private function getCAinfo() {
        if ($this->hasCAinfo()) {
            return $this->cainfo;
        } else {
            return null;
        }
    }

    /**
     * Set the SSL key password.
     * 
     * @param string $CAinfo
     * @return boolean
     */
    public function setSSLkeypasswd($keypass) {
        $this->sslkeypsswd = $keypass;
    }

    private function _hasCAinfo() {
        return !empty($this->sslkeypsswd);
    }

    private function _getCAinfo() {
        if ($this->_hasCAinfo()) {
            return $this->sslkeypsswd;
        } else {
            return null;
        }
    }

    /**
     * This method sets the CAS user's login name.
     *
     * @param $user the login name of the authenticated user.
     *
     * @private
     */
    private function _setUser($user) {
        $this->ST_User = $user;
    }

    /**
     * Tells if a CAS client is a CAS proxy or not
     *
     * @return true when the CAS client is a CAs proxy, false otherwise
     */
    public function isProxy() {
        return $this->_useProxy;
    }

    /**
     * Return headers as array from CURL response.
     * 
     * @param string $response The CURL response.
     * @return array Array of headers
     */
    private function _get_headers_from_curl_response($response) {
        $headers = array();
        $header_text = substr($response, 0, strpos($response, "\r\n\r\n"));
        foreach (explode("\r\n", $header_text) as $i => $line) {
            if ($i === 0) {
                $headers['http_code'] = $line;
            } else {
                list ($key, $value) = explode(': ', $line);
                $headers[$key] = $value;
            }
        }

        return $headers;
    }

    /**
     * Sets the _error property with the last error encountered.
     * 
     * To get the last error executed the method getLastError().
     * 
     * @param string $code Short description of the error.
     * @param string $msg Long description of the error.
     */
    private function _setError($code, $msg, $function) {
        $lastError = new stdClass();
        $lastError->code = $code;
        $lastError->message = $msg;
        $lastError->classFunction = implode('::', array(__CLASS__, $function));

        $this->_error = $lastError;

        error_log($lastError->classFunction . "->" . $lastError->code . " - " . $lastError->message);
    }

    /**
     * 
     * @return string
     */
    public function getLastError() {
        if (property_exists($this, "_error")) {
            return $this->_error;
        }
    }

    private function _getBodyText($html) {
        $dom = new domDocument('1.0', 'utf-8');
        $dom->loadHTML($html);
        $dom->preserveWhiteSpace = false;
        $h3Tag = $dom->getElementsByTagName('h3');
        if ($h3Tag->length == 0) { //expected h3 tag if not get body.
            $bodyTag = $dom->getElementsByTagName('body');
            if ($bodyTag->length == 0) {
                $message = $html; //not found any expected tags.
            } else {
                $message = $bodyTag->item(0)->nodeValue;
            }
        } else {
            $message = $h3Tag->item(0)->nodeValue;
        }

        return $message;
    }

    private function _setProxies($proxies) {
        $this->_proxies = $proxies;
    }

    public function getProxies() {
        if ($this->_hasProxies()) {
            return $this->_proxies;
        }
    }

    private function _hasProxies() {
        return !empty($this->_proxies);
    }

}

?>
