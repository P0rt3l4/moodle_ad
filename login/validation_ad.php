<?php

use core_question\bank\view;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot.'/auth/oidc/auth.php');
use auth_oidc\loginflow\base;
use auth_oidc\jwt;
class validate_ad extends auth_plugin_oidc{

    public $clientid;
    public $clientsecret;
    public $scope = "user.read openid profile offline_access";
    public $grant_type = "password";
    public $none;

    protected function proccess_idtoken($idtoken, $orignonce=''){
        // Decode and verify idtoken.
        $idtoken = jwt::instance_from_encoded($idtoken);
        $sub = $idtoken->claim('sub');
        if (empty($sub)) {
            \auth_oidc\utils::debug('Invalid idtoken', 'base::process_idtoken', $idtoken);
            throw new \moodle_exception('errorauthinvalididtoken', 'auth_oidc');
        }
        $receivednonce = $idtoken->claim('nonce');
        if (!empty($orignonce) && (empty($receivednonce) || $receivednonce !== $orignonce)) {
            \auth_oidc\utils::debug('Invalid nonce', 'base::process_idtoken', $idtoken);
            throw new \moodle_exception('errorauthinvalididtoken', 'auth_oidc');
        }

        // Use 'oid' if available (Azure-specific), or fall back to standard "sub" claim.
        $oidcuniqid = $idtoken->claim('oid');
        if (empty($oidcuniqid)) {
            $oidcuniqid = $idtoken->claim('sub');
        }
        return [$oidcuniqid, $idtoken];
    }

    public function user_ad($user_email,$password){
        global $CFG,$DB;

        $existinguserparams = ['username' => $user_email, 'mnethostid' => $CFG->mnet_localhost_id];
        $userexisting = $DB->get_record('user', $existinguserparams);

        if($userexisting){
            $access_token = $this->get_access_token($userexisting->email,$password);
        }else{
            $access_token = $this->get_access_token($user_email,$password);
        }

        if(empty($access_token->error)){
            [$oidcuniqid, $idtoken] = $this->proccess_idtoken($access_token->access_token);
            $username = $idtoken->claim('upn');
            $tokenrec = $this->createtoken($oidcuniqid,$username,$access_token->access_token,(array)$access_token,$idtoken,0);
           $user_info = $this->get_info_user($access_token);

           if(!$userexisting){
                if (empty($CFG->authpreventaccountcreation)) {
                    $user =$this->create_new_user($user_info);
                }else{
                    // Trigger login failed event.
                    $failurereason = AUTH_LOGIN_NOUSER;
                    $eventdata = ['other' => ['username' => $user_email, 'reason' => $failurereason]];
                    $event = \core\event\user_login_failed::create($eventdata);
                    $event->trigger();
                    throw new \moodle_exception('errorauthloginfailednouser', 'auth_oidc', null, null, '1');
                }
           }else{
                if($userexisting->auth != 'oidc'){
                    $user_email = $userexisting->username = $user_info->userPrincipalName;
                    $userexisting->auth = "oidc";
                    $this->update_user($userexisting);
                }
           }

           $user = authenticate_user_login($user_email, null, true);

           if (!empty($user)) {
                complete_user_login($user);
           }else{
                redirect($CFG->wwwroot, get_string('errorauthgeneral', 'auth_oidc'), null, \core\output\notification::NOTIFY_ERROR);
           }
        }

    }

    protected function get_access_token($user_email,$password){
        $this->none  = rand();
        $postField = "client_id={$this->config->clientid}&scope={$this->scope}&client_secret={$this->config->clientsecret}&username={$user_email}&password={$password}&grant_type={$this->grant_type}&nonce={$this->none}";
        $curl = curl_init();

        curl_setopt_array($curl, 
            array(
                CURLOPT_URL => 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_ENCODING => '',
                CURLOPT_MAXREDIRS => 10,
                CURLOPT_TIMEOUT => 0,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_CUSTOMREQUEST => 'POST',
                CURLOPT_POSTFIELDS => $postField,
                CURLOPT_HTTPHEADER => array(
                    'Content-Type: application/x-www-form-urlencoded'
                ),
            )
        );

        $response = curl_exec($curl);
        
        curl_close($curl);
        return json_decode($response);
    }

    protected function get_info_user($access_token){
        $curl = curl_init();

        curl_setopt_array($curl, array(
          CURLOPT_URL => 'https://graph.microsoft.com/v1.0/me/',
          CURLOPT_RETURNTRANSFER => true,
          CURLOPT_ENCODING => '',
          CURLOPT_MAXREDIRS => 10,
          CURLOPT_TIMEOUT => 0,
          CURLOPT_FOLLOWLOCATION => true,
          CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
          CURLOPT_CUSTOMREQUEST => 'GET',
          CURLOPT_HTTPHEADER => array(
            "Authorization: Bearer {$access_token->access_token}"
          ),
        ));
        
        $response = curl_exec($curl);
        
        curl_close($curl);

        return json_decode($response);
    }

    protected function create_new_user($user){
        global $CFG, $DB, $SESSION;
        require_once($CFG->dirroot.'/user/profile/lib.php');
        require_once($CFG->dirroot.'/user/lib.php');
        $firstname = $user->givenName;
        $lastname = substr($user->displayName,strlen($user->givenName)+1);
        // Just in case check text case.
        $username = trim(core_text::strtolower($username));
        $newuser = new stdClass();
        $newuser->firstname = $firstname;
        $newuser->lastname = $lastname;
        $newuser->email= $user->userPrincipalName;
        $newuser->city = '';
        $newuser->auth = 'oidc';
        $newuser->username = $user->userPrincipalName;
        $newuser->lang = get_newuser_language();
        $newuser->confirmed = 1;
        $newuser->lastip = getremoteaddr();
        $newuser->timecreated = time();
        $newuser->timemodified = $newuser->timecreated;
        $newuser->mnethostid = $CFG->mnet_localhost_id;
        $newuser->id = user_create_user($newuser, false, false);
        // Trigger event.
        \core\event\user_created::create_from_userid($newuser->id)->trigger();

        return $newuser;
    }
    /**
     * Create a token for a user, thus linking a Moodle user to an OpenID Connect user.
     *
     * @param string $oidcuniqid A unique identifier for the user.
     * @param array $username The username of the Moodle user to link to.
     * @param array $authparams Parameters receieved from the auth request.
     * @param array $tokenparams Parameters received from the token request.
     * @param jwt $idtoken A JWT object representing the received id_token.
     * @param int $userid
     * @param null|string $originalupn
     * @return stdClass The created token database record.
     */
    protected function createtoken($oidcuniqid, $username, $authparams, $tokenparams, jwt $idtoken, $userid = 0,
        $originalupn = null) {
        global $DB;

        if (!is_null($originalupn)) {
            $oidcusername = $originalupn;
        } else {
            // Determine remote username. Use 'upn' if available (Azure-specific), or fall back to standard 'sub'.
            $oidcusername = $idtoken->claim('upn');
            if (empty($oidcusername)) {
                $oidcusername = $idtoken->claim('sub');
            }
        }

        // We should not fail here (idtoken was verified earlier to at least contain 'sub', but just in case...).
        if (empty($oidcusername)) {
            throw new \moodle_exception('errorauthinvalididtoken', 'auth_oidc');
        }

        // Cleanup old invalid token with the same oidcusername.
        $DB->delete_records('auth_oidc_token', ['oidcusername' => $oidcusername]);

        // Handle "The existing token for this user does not contain a valid user ID" error.
        if ($userid == 0) {
            $userrec = $DB->get_record('user', ['username' => $username]);
            if ($userrec) {
                $userid = $userrec->id;
            }
        }

        $tokenrec = new stdClass;
        $tokenrec->oidcuniqid = $oidcuniqid;
        $tokenrec->username = $username;
        $tokenrec->userid = $userid;
        $tokenrec->oidcusername = $oidcusername;
        $tokenrec->scope = !empty($tokenparams['scope']) ? $tokenparams['scope'] : 'openid profile email';
        $tokenrec->tokenresource = !empty($tokenparams['resource']) ? $tokenparams['resource'] : $this->config->oidcresource;
        $tokenrec->scope = !empty($tokenparams['scope']) ? $tokenparams['scope'] : $this->config->oidcscope;
        $tokenrec->authcode = $tokenparams['access_token'];//Se cambia $authparams['code'] por $tokenparams['access_token']
        $tokenrec->token = $tokenparams['access_token'];
        if (!empty($tokenparams['expires_on'])) {
            $tokenrec->expiry = $tokenparams['expires_on'];
        } else if (isset($tokenparams['expires_in'])) {
            $tokenrec->expiry = time() + $tokenparams['expires_in'];
        } else {
            $tokenrec->expiry = time() + DAYSECS;
        }
        $tokenrec->refreshtoken = !empty($tokenparams['refresh_token']) ? $tokenparams['refresh_token'] : ''; // TBD?
        $tokenrec->idtoken = $tokenparams['id_token'];
        $tokenrec->id = $DB->insert_record('auth_oidc_token', $tokenrec);
        return $tokenrec;
    }

    protected function update_user($userupdated){
        global $CFG, $DB, $SESSION;
        require_once($CFG->dirroot.'/user/profile/lib.php');
        require_once($CFG->dirroot.'/user/lib.php');
        user_update_user($userupdated,false);

    }
}