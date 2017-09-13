<?php
use \Firebase\JWT\JWT;

class Controller_Base extends Controller_Rest {
    protected $format = 'json';
    protected $key = "example_key";
    /**
     *
     * get response code
     * @param string $code
     * @param array $data
     * @param string or array $message
     *
     * @return json format
     */
    public function get_response($code, $data = '', $message = '') {
        // $token = $this->createToken($data);
        // $data['access-token'] = $token;
        $response = $this->response(array(
            'meta' => array(
                'code'      => $code,
                'message'   => $message
                ),
            'data' => $data
            )
        );

        return $response;
    }

    public function createToken($data) {
        
        $issuedAt   = time();
        $notBefore  = $issuedAt + 10;             //Adding 10 seconds
        $expire     = $notBefore + 60*60*24*365;

        $token = array(
            "iss" => "http://example.org",
            "aud" => "http://example.com",
            "iat" => $issuedAt,
            "nbf" => $notBefore,
            "exp" => $expire,
            "data" => $data
        );


        $jwt = JWT::encode($token, $this->key);
        return $jwt;
    }

    public function getToken($jwt) {
        list($jwt) = sscanf($jwt, 'Bearer %s');

        $token = JWT::decode($jwt, $this->key, array('HS256'));
        return $token;
    }
}