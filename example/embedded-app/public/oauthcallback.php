<?php

require __DIR__ . '/../vendor/autoload.php';

use MailiumOauthClient\MailiumOauthClient;

function storeToken($resourceOwner, $token)
{
    $_SESSION['token'] = $token;
}


session_start();


$oauthClient = new MailiumOauthClient();
$oauthClient->setClientID(getenv('MAILIUM_APP_CLIENT_ID'));
$oauthClient->setClientSecret(getenv('MAILIUM_APP_CLIENT_SECRET'));
$oauthClient->setRedirectUri('http://' . $_SERVER['HTTP_HOST'] . '/oauthcallback.php', true);
$oauthClient->addScope(MailiumOauthClient::SCOPE_BASIC);
$oauthClient->addScope(MailiumOauthClient::SCOPE_CAMPAIGN_READ);
$oauthClient->addScope(MailiumOauthClient::SCOPE_SUBSCRIBER_LIST_READ);

$oauthClient->setTokenStoreCallbackFunction('storeToken');


if (!isset($_GET['code'])) {

    $authorizationUrl = $oauthClient->createAuthorizationUrl();

    // Generate JavaScript Code for redirection
    print $oauthClient->createEmbeddedAppHtmlForRedirection($authorizationUrl);


} else {

    print_r($_GET);
    $authorizationCode = $_GET['code'];
    $authorizationState = $_GET['state'];
    if ($_SESSION['state'] !== $authorizationState) {
        print "<h3>State is not same!!!</h3>";
        exit();
    }
    $oauthClient->authorize($authorizationCode);

    unset($_GET['state']);

    // Redirect to Index
    header('Location: ' . filter_var('http://' . $_SERVER['HTTP_HOST'], FILTER_SANITIZE_URL));
}

