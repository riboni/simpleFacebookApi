<?php
/*
* FacebookAuthenticator PHP class - Wrapper to Facebook API
*
* @pakage FACEBOOK_API_PHP
* @author Giuliano Riboni <giuliano@riboni.com.br>
* @copyright 2012 Giuliano Riboni
* @date 2012-08-30
* @version 1.0.0
* Facebook Documentation:
* https://developers.facebook.com/docs/
* https://developers.facebook.com/docs/authentication/permissions/
*
* Based on Facebook class
* @author Naitik Shah <naitik@facebook.com>
* https://www.facebook.com/note.php?note_id=132257626809081
*/
class FacebookAuthenticator{
  //Variables;
  var $facebookAuthenticatorVersion = '1.0.0';
  var $curlDefaultOptions           = array(CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 60, CURLOPT_USERAGENT => 'facebook-php-2.0');
  var $dropQueryParameters          = array('session');
  var $domainMap                    = array('api' => 'https://api.facebook.com/', 'api_read' => 'https://api-read.facebook.com/', 'graph' => 'https://graph.facebook.com/', 'www' => 'https://www.facebook.com/');
  var $defaultPermissions           = array();
  var $sessionLoaded                = false;
  var $cookieSupport                = false;
  var $canRun                       = true;
  var $baseDomain                   = false;
  var $baseCookiePath               = '/';
  var $baseCookieTimeout            = 31556926; //1 year;
  var $appId;
  var $apiSecret;
  var $session;

  //Constructor;
  function FacebookAuthenticator($appId, $apiSecret, $domain = false, $cookie = false, $defaultPermissions = false){
    //Validate if we can run this class;
    if( !function_exists('curl_init') ){
      $this -> canRun = false;
    }
    if( !function_exists('json_decode') ){
      $this -> canRun = false;
    }
    $this -> setAppId( $appId );
    $this -> setApiSecret( $apiSecret );
    if( $domain !== false ){
      $this -> setBaseDomain( $domain );
    }
    if( $cookie !== false ){
      $this -> setCookieSupport( true );
    }
    if( $defaultPermissions !== false && is_array( $defaultPermissions ) ){
      $this -> setDefaultPermissions( $defaultPermissions );
    }
  }

  //Basic Class Methods;
  function setAppId($appId){
    $this -> appId = $appId;
  }

  function getAppId(){
    return $this -> appId;
  }

  function setApiSecret($apiSecret){
    $this -> apiSecret = $apiSecret;
  }

  function getApiSecret(){
    return $this->apiSecret;
  }

  function setCookieSupport($cookieSupport){
    $this -> cookieSupport = $cookieSupport;
  }

  function useCookieSupport(){
    return $this -> cookieSupport;
  }

  function setDefaultPermissions($defaultPermissions){
    $this -> defaultPermissions = $defaultPermissions;
  }

  function setBaseCookiePath($cookiePath){
    $this -> baseCookiePath = $cookiePath;
  }

  function getBaseCookiePath(){
    return $this -> baseCookiePath;
  }

  function setBaseCookieTimeout($cookieTimeout){
    $this -> baseCookieTimeout = $cookieTimeout;
  }

  function getBaseCookieTimeout(){
    return $this -> baseCookieTimeout;
  }

  function setBaseDomain($domain){
    $this -> baseDomain = $domain;
  }

  function getBaseDomain(){
    return $this -> baseDomain;
  }

  function setSession($session, $writeCookie = true){
    $session               = $this -> validateSessionObject( $session );
    $this -> sessionLoaded = true;
    $this -> session       = $session;
    if( $writeCookie === true ){
      $this -> setCookieFromSession( $session );
    }
  }

  function getSession(){
    if( !$this -> sessionLoaded ){
      $session     = null;
      $writeCookie = true;
      //Try loading session from $_REQUEST;
      if( isset( $_REQUEST['session'] ) ){
        $session = json_decode(
          get_magic_quotes_gpc()
            ? stripslashes($_REQUEST['session'])
            : $_REQUEST['session'],
          true
        );
        $session = $this -> validateSessionObject( $session );
      }
      //Try loading session from cookie if necessary;
      if( !$session && $this -> useCookieSupport() ){
        $cookieName = $this -> getSessionCookieName();
        if( isset( $_COOKIE[$cookieName] ) ){
          $session = array();
          parse_str(trim(
            get_magic_quotes_gpc()
              ? stripslashes($_COOKIE[$cookieName])
              : $_COOKIE[$cookieName],
            '"'
          ), $session);
          $session = $this -> validateSessionObject( $session );
          //write only if we need to delete a invalid session cookie;
          $writeCookie = empty($session);
        }
      }
      $this -> setSession($session, $writeCookie);
    }
    if( !empty( $this -> session ) ){
      return $this -> session;
    }else{
      return false;
    }
  }

  function getUser(){
    $session = $this -> getSession();
    return $session ? $session['uid'] : null;
  }

  public function getUserId(){
    $uid = $this -> getUser();
    if( !empty( $uid ) ){
      return $uid;
    }else{
      return false;
    }
  }

  public function getUserInfo($key = false){
    if( !$this -> getSession() ){
      return false;
    }
    $userInfo = $this -> api('/me');
    if( !empty( $userInfo ) ){
      if( $key == false ){
        return $userInfo;
      }else{
        return $userInfo[ $key ];
      }
    }else{
      return false;
    }
  }

  public function getLoginUrl($permissionArray = false, $okRedirectUrl = false, $errorRedirectUrl = false){
    $apiArray = array();
    //Make the permission array;
    if( is_array($this->defaultPermissions) && sizeof($this->defaultPermissions) > 0 ){
      $permissionFinalArray = $this->defaultPermissions;
    }else{
      $permissionFinalArray = array();
    }
    if( is_array($permissionArray) && sizeof($permissionArray) > 0 ){
      $permissionFinalArray = array_merge($permissionFinalArray, $permissionArray);
    }
    if( is_array($permissionFinalArray) && sizeof($permissionFinalArray) > 0 ){
      $apiArray['req_perms'] = implode(',', $permissionFinalArray);
    }
    //Make the next and cancel;
    if( $okRedirectUrl !== false ){
      $apiArray['next'] = $okRedirectUrl;
    }else{
      $apiArray['next'] = false;
    }
    if( $errorRedirectUrl !== false ){
      $apiArray['cancel_url'] = $errorRedirectUrl;
    }else{
      $apiArray['cancel_url'] = false;
    }
    return $this -> _getLoginUrl( $apiArray );
  }

  function _getLoginUrl($params = array()){
    if( isset( $params['cancel_url'] ) && $params['cancel_url'] != false ){
      $cancelUrl = $params['cancel_url'];
    }else{
      $cancelUrl = $this -> getCurrentUrl();
    }
    if( isset( $params['next'] ) && $params['next'] != false ){
      $nextUrl = $params['next'];
    }else{
      $nextUrl = $this -> getCurrentUrl();
    }
    return $this -> getUrl(
      'www',
      'login.php',
      array_merge(array(
        'api_key'         => $this -> getAppId(),
        'cancel_url'      => $cancelUrl,
        'display'         => 'page',
        'fbconnect'       => 1,
        'next'            => $nextUrl,
        'return_session'  => 1,
        'session_version' => 3,
        'v'               => '1.0',
      ), $params)
    );
  }

  function getLogoutUrl($params = array()){
    $session = $this -> getSession();
    if( isset( $params['next'] ) && $params['next'] != false ){
      $nextUrl = $params['next'];
    }else{
      $nextUrl = $this -> getCurrentUrl();
    }
    return $this -> getUrl(
      'www',
      'logout.php',
      array_merge(array(
        'api_key'     => $this -> getAppId(),
        'next'        => $nextUrl,
        'session_key' => $session['session_key'],
      ), $params)
    );
  }

  function getLoginStatusUrl($params = array()){
    return $this -> getUrl(
      'www',
      'extern/login_status.php',
      array_merge(array(
        'api_key'         => $this -> getAppId(),
        'no_session'      => $this -> getCurrentUrl(),
        'no_user'         => $this -> getCurrentUrl(),
        'ok_session'      => $this -> getCurrentUrl(),
        'session_version' => 3,
      ), $params)
    );
  }

  function api(/* polymorphic */){
    $args = func_get_args();
    if( is_array( $args[0] ) ){
      return $this -> _restserver( $args[0] );
    }else{
      return call_user_func_array(array($this, '_graph'), $args);
    }
  }

  function _restserver($params){
    //Generic application level parameters;
    $params['api_key'] = $this -> getAppId();
    $params['format']  = 'json-strings';
    $result = json_decode($this -> _oauthRequest($this -> getApiUrl($params['method']), $params), true);
    //Results are returned, errors are thrown;
    if( is_array( $result ) && isset( $result['error_code'] ) ){
      return false;
    }
    return $result;
  }

  function _graph($path, $method = 'GET', $params = array()){
    if( is_array( $method ) && empty( $params ) ){
      $params = $method;
      $method = 'GET';
    }
    //Method override as we always do a POST;
    $params['method'] = $method;
    $result = json_decode($this -> _oauthRequest($this -> getUrl('graph', $path), $params), true);
    if( is_array( $result ) && isset( $result['error'] ) ){
      $this -> setSession( null );
      return false;
    }
    return $result;
  }

  function _oauthRequest($url, $params){
    if( !isset( $params['access_token'] ) ){
      $session = $this -> getSession();
      //Either user session signed, or app signed;
      if( $session ){
        $params['access_token'] = $session['access_token'];
      }else{
        $params['access_token'] = $this -> getAppId().'|'.$this -> getApiSecret();
      }
    }
    //Json_encode all params values that are not strings;
    foreach($params as $key => $value){
      if( !is_string( $value ) ){
        $params[$key] = json_encode( $value );
      }
    }
    return $this -> makeRequest($url, $params);
  }

  function makeRequest($url, $params, $ch = null){
    if( !$ch ){
      $ch = curl_init();
    }
    $opts                         = $this -> curlDefaultOptions;
    $opts[CURLOPT_SSL_VERIFYPEER] = false;
    $opts[CURLOPT_POSTFIELDS]     = $params;
    $opts[CURLOPT_URL]            = $url;
    curl_setopt_array($ch, $opts);
    $result = curl_exec( $ch );
    if( $result === false ){
      curl_close( $ch );
      return false;
    }
    curl_close( $ch );
    return $result;
  }

  function getSessionCookieName(){
    return 'facebookCookie_'.$this -> getAppId();
  }

  function setCookieFromSession($session = null){
    if( !$this -> useCookieSupport() ){
      return false;
    }
    $cookieName = $this -> getSessionCookieName();
    $value      = 'noCookie';
    $expires    = time() + $this -> baseCookieTimeout;
    if( $session ){
      $value = '"'.http_build_query($session, null, '&').'"';
    }
    //If an existing cookie is not set, we dont need to delete it;
    if($value == 'noCookie' && empty( $_COOKIE[ $cookieName ] ) ){
      return false;
    }
    if( headers_sent() ){
      return false;
    }else{
      if( $this -> getBaseDomain() != false ){
        setcookie($cookieName, $value, $expires, $this -> baseCookiePath, $this -> getBaseDomain());
      }else{
        setcookie($cookieName, $value, $expires, $this -> baseCookiePath);
      }
    }
  }

  function validateSessionObject($session){
    //Make sure some essential fields exist;
    if( is_array( $session ) && isset( $session['uid'] ) && isset( $session['session_key'] ) && isset( $session['secret'] ) && isset( $session['access_token'] ) && isset( $session['sig'] ) ){
      //Validate the signature;
      $sessionWithoutSig = $session;
      unset( $sessionWithoutSig['sig'] );
      $expectedSig = $this -> generateSignature($sessionWithoutSig, $this -> getApiSecret());
      if( $session['sig'] != $expectedSig ){
        $session = null;
      }
    }else{
      $session = null;
    }
    return $session;
  }

  function getApiUrl($method){
    $readOnlyCalls =
      array('admin.getallocation' => 1,
            'admin.getappproperties' => 1,
            'admin.getbannedusers' => 1,
            'admin.getlivestreamvialink' => 1,
            'admin.getmetrics' => 1,
            'admin.getrestrictioninfo' => 1,
            'application.getpublicinfo' => 1,
            'auth.getapppublickey' => 1,
            'auth.getsession' => 1,
            'auth.getsignedpublicsessiondata' => 1,
            'comments.get' => 1,
            'connect.getunconnectedfriendscount' => 1,
            'dashboard.getactivity' => 1,
            'dashboard.getcount' => 1,
            'dashboard.getglobalnews' => 1,
            'dashboard.getnews' => 1,
            'dashboard.multigetcount' => 1,
            'dashboard.multigetnews' => 1,
            'data.getcookies' => 1,
            'events.get' => 1,
            'events.getmembers' => 1,
            'fbml.getcustomtags' => 1,
            'feed.getappfriendstories' => 1,
            'feed.getregisteredtemplatebundlebyid' => 1,
            'feed.getregisteredtemplatebundles' => 1,
            'fql.multiquery' => 1,
            'fql.query' => 1,
            'friends.arefriends' => 1,
            'friends.get' => 1,
            'friends.getappusers' => 1,
            'friends.getlists' => 1,
            'friends.getmutualfriends' => 1,
            'gifts.get' => 1,
            'groups.get' => 1,
            'groups.getmembers' => 1,
            'intl.gettranslations' => 1,
            'links.get' => 1,
            'notes.get' => 1,
            'notifications.get' => 1,
            'pages.getinfo' => 1,
            'pages.isadmin' => 1,
            'pages.isappadded' => 1,
            'pages.isfan' => 1,
            'permissions.checkavailableapiaccess' => 1,
            'permissions.checkgrantedapiaccess' => 1,
            'photos.get' => 1,
            'photos.getalbums' => 1,
            'photos.gettags' => 1,
            'profile.getinfo' => 1,
            'profile.getinfooptions' => 1,
            'stream.get' => 1,
            'stream.getcomments' => 1,
            'stream.getfilters' => 1,
            'users.getinfo' => 1,
            'users.getloggedinuser' => 1,
            'users.getstandardinfo' => 1,
            'users.hasapppermission' => 1,
            'users.isappuser' => 1,
            'users.isverified' => 1,
            'video.getuploadlimits' => 1);
    $name = 'api';
    if( isset( $readOnlyCalls[ strtolower( $method ) ] ) ){
      $name = 'api_read';
    }
    return $this -> getUrl($name, 'restserver.php');
  }

  function getUrl($name, $path = '', $params = array()){
    $url = $this -> domainMap[ $name ];
    if( $path ){
      if( $path[0] === '/' ){
        $path = substr($path, 1);
      }
      $url .= $path;
    }
    if( $params ){
      $url .= '?'.http_build_query( $params );
    }
    return $url;
  }

  function getCurrentUrl(){
    $protocol   = isset( $_SERVER['HTTPS'] ) && $_SERVER['HTTPS'] == 'on' ? 'https://' : 'http://';
    $currentUrl = $protocol.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
    $parts      = parse_url( $currentUrl );
    $query      = '';
    if( !empty( $parts['query'] ) ){
      $params = array();
      parse_str($parts['query'], $params);
      foreach($this -> dropQueryParameters as $key){
        unset( $params[ $key ] );
      }
      if( !empty( $params ) ){
        $query = '?'.http_build_query( $params );
      }
    }
    //Use port if non default;
    $port = isset( $parts['port'] ) && ( ( $protocol === 'http://' && $parts['port'] !== 80 ) || ( $protocol === 'https://' && $parts['port'] !== 443 ) ) ? ':' . $parts['port'] : '';
    //Rebuild;
    return $protocol.$parts['host'].$port.$parts['path'].$query;
  }

  function generateSignature($params, $secret){
    //Work with sorted data;
    ksort( $params );
    //Generate the base string;
    $baseString = '';
    foreach($params as $key => $value){
      $baseString .= $key.'='.$value;
    }
    $baseString .= $secret;
    return md5( $baseString );
  }

  public function hasPermission($permission){
    if( !$this -> getSession() ){
      return false;
    }
    $uid                = $this -> getUserId();
    $api_call           = array('method' => 'users.hasAppPermission', 'uid' => $uid, 'ext_perm' => $permission);
    $usersHasPermission = $this -> api( $api_call );
    if( $usersHasPermission == 1 ){
      return true;
    }else{
      return false;
    }
  }

  public function postWall($message = false, $name = false, $description = false, $caption = false, $picture = false, $link = false){
    if( !$this -> getSession() ){
      return false;
    }
    if( $this -> hasPermission('publish_stream') ){
      $uid                       = $this -> getUserId();
      $postValues                = array();
      if( $message !== false ){
        $postValues['message'] = $message;
      }
      if( $name !== false ){
        $postValues['name'] = $name;
      }
      if( $description !== false ){
        $postValues['description'] = $description;
      }
      if( $caption !== false ){
        $postValues['caption'] = $caption;
      }
      if( $picture !== false ){
        $postValues['picture'] = $picture;
      }
      if( $link !== false ){
        $postValues['link'] = $link;
      }
      $posted = $this -> api('/'.$uid.'/feed', 'post', $postValues);
      if( isset( $posted['id'] ) ){
        return true;
      }else{
        return false;
      }
    }else{
      return false;
    }
  }
}
