<?php
use \Firebase\JWT\JWT;
define('ISSUED_AT', time());
define('NOT_BEFORE', ISSUED_AT + 10);
define('EXPIRED', NOT_BEFORE + 60*60*24*365);


class Controller_Base extends Controller_Rest {
    protected $format = 'json';
    protected $key = 'hifood2017:azf56vqu';
    /**
     *
     * get response code
     * @param string $code
     * @param array $data
     * @param $token string 'new' => create, string 'asd98f98f' => update, boolean 'false' => do nothing
     * @param string or array $message
     *
     * @return json format
     */
    public function get_response($code, $data = '', $token = '', $message = '') {
        if ($token) {
            if ($token == 'new')
                $token = $this->createToken($data);
            else
                $token = $this->updateToken($token);

            $data->{'access-token'} = $token;
        }

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

        $token = array(
            "iss" => "http://example.org",
            "aud" => "http://example.com",
            "iat" => ISSUED_AT,
            "nbf" => NOT_BEFORE,
            "exp" => EXPIRED,
            "data" => $data
        );


        $jwt = JWT::encode($token, base64_encode($this->key));
        return $jwt;
    }

    public function updateToken($key_token) {

        $token = $this->getToken($key_token);
        $token->iat = ISSUED_AT;
        $token->nbf = NOT_BEFORE;
        $token->exp = EXPIRED;

        $jwt = JWT::encode($token, base64_encode($this->key));
        return $jwt;
    }

    public function getToken($token) {
        $token = JWT::decode($token, base64_encode($this->key), array('HS256'));
        return $token;
    }

    public function checkToken($token) {
        try {
            $token = $this->getToken($token);
            return $token;
        }
        catch(Exception $e) {
            $res = new stdClass();
            $res->success = false;
            $res->messages = $e->getMessage();
            return $res;
        }
        
    }

    private function checkAuthorization($auth) {
        list($auth) = sscanf($auth, 'Bearer %s');
        if (base64_decode($auth) === $this->key)
            return true;

        return false;
    }
}