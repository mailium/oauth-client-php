# Mailium Oauth Client for PHP
[![Latest Stable Version](https://poser.pugx.org/mailium/oauth-client-php/v/stable.svg)](https://packagist.org/packages/mailium/oauth-client-php) [![Monthly Downloads](https://poser.pugx.org/mailium/oauth-client-php/d/monthly.png)](https://packagist.org/packages/mailium/oauth-client-php) [![License](https://poser.pugx.org/mailium/oauth-client-php/license.svg)](https://packagist.org/packages/mailium/oauth-client-php) ![Build Status](https://travis-ci.org/mailium/oauth-client-php.svg?branch=master)



Mailium Oauth Client provides easy to use wrappers for authorizing your application and getting the tokens required to talk to the API.

## Example application

An example application can be found under example directory.

This is a simple working application that utilizes most of the features of the client.

## Quick Start

### First, let's install the library with composer:

```bash
    composer require mailium/oauth-client-php
```

### Initialize the client with your client_id and client_secret

```php
$oauthClient = new MailiumOauthClient();
$oauthClient->setClientID("YOUR_CLIENT_ID");
$oauthClient->setClientSecret("YOUR_CLIENT_SECRET");
$oauthClient->setRedirectUri("YOUR_REDIRECT_URI");

// Scopes that your application need
$oauthClient->addScope(MailiumOauthClient::SCOPE_BASIC);
$oauthClient->addScope(MailiumOauthClient::SCOPE_CAMPAIGN_READ);
$oauthClient->addScope(MailiumOauthClient::SCOPE_SUBSCRIBER_LIST_READ);

// Set the callback method to store the oauth token
$oauthClient->setTokenStoreCallbackFunction("storeToken");
```

### Creating authorization URL

```php
$authorizationUrl = $oauthClient->createAuthorizationUrl();
```


### Getting the tokens after receiving the authorization code

```php
$oauthClient->authorize($authorizationCode);
```

### Getting Resource Owner

```php
$oauthClient->getResourceOwner();
```