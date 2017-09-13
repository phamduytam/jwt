<?php
/**
 *
 * @version 1
 */

class Controller_Users extends Controller_Base {

    private $_filter = array('strip_tags', 'htmlentities');

    /**
     * @api
     *
     * Create user account
     *
     * @return json format
     */
    public function post_create() {
        // Init
        $model = new Model_V1_Users();

        // add validation
        $val = Validation::forge()->add_model('Model_V1_Users');
        if ($val->run()) {
            // create user
            $rest = Auth::create_user(
                Security::clean(Input::param('username'), $this->_filter),
                Security::clean(Input::param('password'), $this->_filter),
                Security::clean(Input::param('email'), $this->_filter),
                1,
                array(
                    'firstname' => Security::clean(Input::param('firstname'), $this->_filter),
                    'lastname'  => Security::clean(Input::param('lastname'), $this->_filter),
                    'avatar'    => Security::clean(Input::param('avatar'), $this->_filter),
                    'birthday'  => Security::clean(Input::param('birthday'), $this->_filter),
                    'gender'    => Security::clean(Input::param('gender'), $this->_filter),
                    'address'   => Security::clean(Input::param('address'), $this->_filter),
                    'city'      => Security::clean(Input::param('city'), $this->_filter),
                    'mobile'    => Security::clean(Input::param('mobile'), $this->_filter)
                )
            );

            if ($rest['code'] !== STATUS_OK) {
                $response = $this->get_response($rest['code'], '', $rest['message']);
            } else {
                $data = Input::param();
                $message = 'User account was created successfully';
                $response = $this->get_response(STATUS_OK, $data, $message);
            }
        } else {
            //get validation message
            $message = array();
            foreach ($val->error() as $field => $error) {
                array_push($message, array($field => $error->get_message()));
            }
            $response = $this->get_response(ERROR_VALIDATE, '', $message);
        }

        return $response;
    }

    /**
     *
     * User Login
     * param HTTP_METHOD POST
     * @return json format
     */
    public function post_signin() {
        // get params
        $username = Security::clean(Input::json('username'), $this->_filter);
        $password = Security::clean(Input::json('password'), $this->_filter);

        $data = array(
            'username' => $username,
            'password' => $password
        );

        $response = $this->get_response(200, $data);

        return $response;
    }

    /**
     *
     * User logout
     * param HTTP_METHOD PUT
     * @return json format
     */
    public function put_logout() {
        $model = new Model_V1_Users();
        $token = Security::clean(Input::put('token'));
        if ($model->check_token($token) and $token != '') {
            //Delete session login_hash and update token = ''
            Auth::logout();
            return $this->get_response(STATUS_OK, '', 'Logout successful!');
        } else {
            return $this->get_response(ERROR_TOKEN_INVALID, '', MSG_TOKEN_INVALID);
        }
    }

    /**
     *
     * Update user info
     *
     * params get from HTTP METHOD PUT
     * @return json format
     */
    public function put_update() {
        $jwt = \Input::headers('Authorization');
        // $jwt = $response->get_header('Authorization');

        $token = $this->getToken($jwt);
        return $this->get_response(200, $token);
        return $token;
    }

    /**
     *
     * Change password
     *
     * params get from method PUT
     * return json format
     */
    public function put_password() {
        // Init model
        $model = new Model_V1_Users();

        $token = Security::clean(Input::put('token'));
         //check token
        if ($model->check_token($token) and $token != '') {
            // Init validation
            $val = Validation::forge()->add_model('Model_V1_Users');
            $data = array('password' => Input::put('new_password'));
            if ($val->run($data, true)) {

                $old_password   = Security::clean(Input::param('old_password'), $this->_filter);
                $new_password   = Security::clean(Input::param('new_password'), $this->_filter);
                $re_password    = Security::clean(Input::param('retype_password'), $this->_filter);
                // check retype_password match with new_password
                if ($new_password !== $re_password) {
                    return $this->get_response(ERROR_PWD_NOT_MATCH, '', MSG_PWD_NOT_MATCH);
                }

                $user_id = Security::clean(Input::put('user_id'));
                // Change password
                $res = Auth::change_password($old_password, $new_password, $user_id);
                if ($res['code'] != STATUS_OK) {
                    return $this->get_response($res['code'], '', $res['message']);
                } else {
                    return $this->get_response(STATUS_OK, $res['data'], 'Change password successful!');
                }

            } else {
                //get validation message
                $message = array();
                foreach ($val->error() as $field => $error) {
                    array_push($message, array($field => $error->get_message()));
                }
                return $this->get_response(ERROR_VALIDATE, '', $message);
            }
        } else {
            return $this->get_response(ERROR_TOKEN_INVALID, '', MSG_TOKEN_INVALID);
        }
    }

    /**
     *
     * Search user by username, firstname, lastname
     * @param string $keyword get from method GET
     * return json format
     */
    public function get_search() {
        $keyword = Security::clean(Input::get('keyword'), $this->_filter);
        if (!$keyword) {
            return $this->get_response(ERROR_KEYWORD_NULL, '', MSG_KEYWORD_NULL);
        }
        // if limit not exist and not nummeric: return default: LIMIT_USER
        $limit = (Input::get('limit') and is_numeric(Input::get('limit'))) ? Security::clean(Input::get('limit'), $this->_filter) : LIMIT_USER;
        // if offset not exist and not nummeric: return default: 0
        $offset = (Input::get('offset') and is_numeric(Input::get('offset'))) ? Security::clean(Input::get('offset'), $this->_filter) : 0;

        // init model
        $model = new Model_V1_Users();
        // search_user
        $res = $model->search_user($keyword, $limit, $offset);
        // check search
        if ($res == false) {
            return $this->get_response(ERROR_SEARCH_USER_FAILED, '', MSG_SEARCH_USER_FAILED);
        }
        //check result
        if ($res['total'] === 0) {
            return $this->get_response(ERROR_SEARCH_USER_NOT_FOUND_RESULT, '', 'result not found');
        }

        return $this->get_response(STATUS_OK, $res, 'Find <span class="red">'.$res['total'].'</span> results with keyword <span class="red">'.$keyword.'</span>');
    }

    /**
     *
     * Get user information
     * return json format
     */
    public function get_user_info() {
        // Init model
        $model = new Model_V1_Users();

        $token = Security::clean(Input::get('token'));
         //check token
        if ($model->check_token($token) and $token != '') {
            $user_id = Security::clean(Input::get('user_id'));
            $user = $model->get_user_info($user_id);
            // exist user
            if ($user !== false) {
                return $this->get_response(STATUS_OK, $user, 'Get information of user successfully!');
            }
            return $this->get_response(ERROR_GET_USER_INFO_FAILED, '', MSG_GET_USER_INFO_FAILED);
        } else {
            return $this->get_response(ERROR_TOKEN_INVALID, '', MSG_TOKEN_INVALID);
        }
    }

}