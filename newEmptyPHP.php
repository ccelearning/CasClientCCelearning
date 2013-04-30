<?php
require_once($_SERVER['DOCUMENT_ROOT'] . '/local/util/CasClientCCelearning/CasClientCCelearning.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/local/util/CasClientCCelearning/config.php');
  $casClient = new CasClientCCelearning(CAS_SERVER, CAS_INSTANCE);

            $proxyTicketParams = array(
                "certs" => array(
                    "sslCertPath" => SSL_CERT,
                    "sslKeyPath" => SSL_KEY,
                    "CAinfoPath" => CA_INFO,
                    "SSLkeypasswd" => SSL_KEY_PASSWORD,
                ),
                "tgtParams" => array(
                    "username" => CAS_USER,
                    "password" => CAS_PASS,
                    "tenant" => "accn",
                ),
                "service" => $casClient->getCurrentURL(),
                "targetService" => "https://accn-portal-prepro.cclearning.accenture.com/user/subscribe",
            );

            //Workaround to fix issues....

            $proxyTicket = $casClient->requestPT_full_process($proxyTicketParams);
            if (!$proxyTicket) {
                $error = $casClient->getLastError();
                var_dump($error);
                die();
            }

            echo "ok";
            
            $data = '{
    "fn": {
        "text": "NombreUsuario"
    },
    "uid": {
        "uri": "50894659Y"
    },
    "n": {
        "given": ["FirstName"],
        "surname": ["LastName"]
    },
    "email": [
        {
            "text": "firstname@organization.com"
        }
    ],
    "org": {
        "text": ["Company"]
    },
    "lang": [
        {
            "language-tag": "es-ES"
        }
    ],
    "role": [
        {
            "parameters": {
		"app":  {
"text": "portal"
}
            },
            "text": "ROLE_USER"
        },
        {
            "parameters": {
		"app": {
"text": "moodle"
}
            },
            "text": "ADMIN"
        }

    ],
    "bday": {
        "date": "19760415"
    },
    "gender": {
        "sex": "M"
    },
    "x-custom-parameters": [
        {
            "id": "x-kipp-role",
            "value": "manager"
        },
        {
            "id": "x-kipp-school",
            "value": "NY School"
        }
    ]
}
';
            
             $postData = json_encode($data);
            // URL for curl
            //Añadimos el ticket a la url que vamos a llamar.
            $serviceUrl = implode("?", array($proxyTicketParams['targetService'],
                http_build_query(array("ticket" => $proxyTicket))
                    )
            );
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $serviceUrl);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
            curl_setopt($ch, CURLOPT_VERBOSE, 3);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
            curl_setopt($ch, CURLOPT_HEADER, 1);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 1);
            curl_setopt($ch, CURLOPT_SSLVERSION, 3);
            curl_setopt($ch, CURLOPT_SSLCERTTYPE, 'PEM');
            curl_setopt($ch, CURLOPT_SSLCERT, SSL_CERT);
            curl_setopt($ch, CURLOPT_SSLKEY, SSL_KEY);
            curl_setopt($ch, CURLOPT_CAINFO, CA_INFO);
            curl_setopt($ch, CURLOPT_SSLKEYPASSWD, SSL_KEY_PASSWORD);

            $response = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $result['header'] = substr($response, 0, $header_size);
        $result['body'] = substr($response, $header_size);
        $result['http_code'] = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            return $code;           
?>
