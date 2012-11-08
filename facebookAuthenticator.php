<?php
/*
* Using the Facebook PHP SDK (v.3.2.0) at https://github.com/facebook/facebook-php-sdk
*/
include_once('facebook/facebook.php');

/*
* FacebookAuthenticator PHP class - Wrapper to Facebook API
*
* @pakage FACEBOOK_API_PHP
* @author Giuliano Riboni <giuliano@riboni.com.br>
* @copyright 2012 Giuliano Riboni
* @date 2012-10-29
* @version 2.0.0
* Facebook Documentation:
* https://developers.facebook.com/docs/
* https://developers.facebook.com/docs/authentication/permissions/
*
* Based on Facebook class
* @author Naitik Shah <naitik@facebook.com>
* https://github.com/facebook/facebook-php-sdk
*/
class FacebookAuthenticator{
  //Variables;
  var $facebookAuthenticatorVersion = '2.0.0';
  var $facebook                     = false;
  var $canRun                       = false;
  var $defaultPermissions           = array();
  var $cookieName                   = 'FacebookCookieBogus';

  //Constructor;
  function FacebookAuthenticator($appId, $apiSecret, $domain = false, $cookie = false, $defaultPermissions = false){
    //Save the values;
    $this -> setAppId($appId);
    $this -> setApiSecret($apiSecret);
    //Make the config array;
    $configArray           = array();
    $configArray['appId']  = $appId;
    $configArray['secret'] = $apiSecret;
    //Start the facebookObject;
    $this -> facebook = new Facebook( $configArray );
    //Loaded;
    $this -> canRun = true;
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

  //Methods;
  function getLoginUrl($permissionArray = false, $okRedirectUrl = false, $errorRedirectUrl = false){
    if( $this -> canRun === false ){
      return false;
    }
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
      $apiArray['redirect_uri'] = $okRedirectUrl;
    }else{
      $apiArray['redirect_uri'] = false;
    }
    if( $errorRedirectUrl !== false ){
      $apiArray['cancel_url'] = $errorRedirectUrl;
    }else{
      $apiArray['cancel_url'] = false;
    }
    return $this -> facebook -> getLoginUrl( $apiArray );
  }

  function getLogoutUrl($params = array()){
    if( $this -> canRun === false ){
      return false;
    }
    $session = $this -> getSession();
    if( isset( $params['next'] ) && $params['next'] != false ){
      //Do Nothing;
    }else{
      $params['next'] = $this -> facebook -> getCurrentUrl();
    }
    return $this -> facebook -> getLogoutUrl($params);
  }

  function getUserId(){
    if( $this -> canRun === false ){
      return false;
    }
    $uid = $this -> facebook -> getUser();
    if( !empty( $uid ) ){
      return $uid;
    }else{
      return false;
    }
  }

  function getUserInfo($key = false){
    if( $this -> canRun === false ){
      return false;
    }
    $userInfo = $this -> facebook -> api('/me');
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

  function isValidSession(){
    return true;
  }

  function getSessionCookieName(){
    $this -> facebook -> destroySession();
    return $this -> cookieName;
  }

  function hasPermission($permission){
    if( $this -> canRun === false ){
      return false;
    }
    $uid                = $this -> getUserId();
    $api_call           = array('method' => 'users.hasAppPermission', 'uid' => $uid, 'ext_perm' => $permission);
    $usersHasPermission = $this -> facebook -> api( $api_call );
    if( $usersHasPermission == 1 ){
      return true;
    }else{
      return false;
    }
  }

  function postWall($message = false, $name = false, $description = false, $caption = false, $picture = false, $link = false){
    if( $this -> canRun === false ){
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
      $posted = $this -> facebook -> api('/'.$uid.'/feed', 'post', $postValues);
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
