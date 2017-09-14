<?php
use \Firebase\JWT\JWT;

class Controller_Base extends Controller_Rest {
    protected $format = 'json';
    protected $key = 'hifood2017:azf56vqu';
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


        $jwt = JWT::encode($token, base64_encode($this->key));
        return $jwt;
    }

    public function updateToken() {
        
    }

    public function getToken($token) {
        $token = JWT::decode($token, $this->key, array('HS256'));
        return $token;
    }

    private function checkAuthorization($auth) {
        list($auth) = sscanf($auth, 'Bearer %s');
        if (base64_decode($auth) === $this->key)
            return true;

        return false;
    }
}