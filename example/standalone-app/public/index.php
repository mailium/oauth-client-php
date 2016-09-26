<?php

require __DIR__ . '/../vendor/autoload.php';

use MailiumOauthClient\MailiumOauthClient;
use MailiumOauthClient\Exception\MailiumOauthClientException;

// function to store the token
function storeToken($resourceOwner, $token)
{
    $_SESSION['token'] = $token;
}
// function to remove the token
function removeToken($resourceOwner)
{
    unset($_SESSION['token']);
}

// Start Session

session_start();


// Create Oauth client
$oauthClient = new MailiumOauthClient();

$oauthClient->setClientID(getenv('MAILIUM_APP_CLIENT_ID'));
$oauthClient->setClientSecret(getenv('MAILIUM_APP_CLIENT_SECRET'));
$oauthClient->setRedirectUri("http://" .  $_SERVER['HTTP_HOST'] . "/oauthcallback.php");

$oauthClient->addScope(MailiumOauthClient::SCOPE_BASIC);
$oauthClient->addScope(MailiumOauthClient::SCOPE_CAMPAIGN_READ);
$oauthClient->addScope(MailiumOauthClient::SCOPE_SUBSCRIBER_LIST_READ);

$oauthClient->setTokenStoreCallbackFunction("storeToken");


print "<h3>Session:</h3>";
print "<pre>";
print_r($_SESSION);
print "</pre>";
print "<hr>";

// Token is stored in the session, if we don't have it we should redirect to authorization URL to get the token
if (!isset($_SESSION['token'])) {
    $state = $oauthClient->generateState();
    unset($_SESSION['state']);
    $_SESSION['state'] = $oauthClient->getState();
    $authorizationUrl = $oauthClient->createAuthorizationUrl();

    print "<h3>Authorization URL To Redirect:</h3>";
    print "<pre>";
    print_r($authorizationUrl);
    print "</pre>";

    // Send redirect to parent for Authorization URL
    $redirectUri = filter_var($authorizationUrl, FILTER_SANITIZE_URL);

    // Redirect To Authorization URL
    header('Location: ' . $redirectUri);

} else {
    try {
        $oauthClient->setToken($_SESSION['token']);
    } catch (\Exception $e) {
        unset ($_SESSION['token']);
    }

    print '<h3><a href="' . 'http://' .  $_SERVER['HTTP_HOST'] . '/index.php"' . '> Index Page </a></h3>';
    print "<hr>";
    print '<h3><a href="' . 'http://' .  $_SERVER['HTTP_HOST'] . '/session.php"' . '> Session Page </a></h3>';
    print "<hr>";
    print '<h3><a href="' . 'http://' .  $_SERVER['HTTP_HOST'] . '/reset_session.php"' . '> Session Reset Page </a></h3>';
    print "<hr>";
    print '<h3><a href="' . 'http://' .  $_SERVER['HTTP_HOST'] . '/oauthcallback.php"' . '> Oauth Callback Page </a></h3>';
    print "<hr>";
    print "<h3>Token in Session:</h3>";
    print "<pre>";
    print_r($_SESSION['token']);
    print "</pre>";
    print "<hr>";

    try {
        $resourceOwner = $oauthClient->getResourceOwner();
    } catch (MailiumOauthClientException $e) {
        if ($e->getCode() === MailiumOauthClientException::ACCESS_DENIED) {
            print "<h3>Access Token Has Been Revoked</h3>";
            removeToken($resourceOwner);
            // Redirect To Authorization URL
            header('Location: ' . $redirectUri);
        } else {
            print "<h3>Exception Occured</h3>";
            print "<pre>";
            print "Exception Message : " . $e->getMessage();
            print "Exception Code : " . $e->getCode();
            print "</pre>";
        }

    } catch (\Exception $e) {
        print "<h3>Exception Occured</h3>";
        var_dump($e);

    }


    print "<h3>Resource Owner</h3>";
    print "<pre>";
    print_r($oauthClient->getResourceOwner());
    print "</pre>";

    print "<h3>Is Token Expired</h3>";
    print "<pre>";
    echo $oauthClient->isAccessTokenExpired() ? "yes" : "no";
    print "</pre>";


    print "<h3>Session:</h3>";
    print "<pre>";
    print_r($_SESSION);
    print "</pre>";
    print "<hr>";

}
