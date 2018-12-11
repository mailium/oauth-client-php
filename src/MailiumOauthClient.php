<?php namespace MailiumOauthClient;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7;
use GuzzleHttp\Exception\RequestException;

use Monolog\Logger;
use Monolog\Handler\StreamHandler;

use MailiumOauthClient\Exception\MailiumOauthClientException;

class MailiumOauthClient
{
    const VERSION = '1.0.19';

    // Available Scopes
    const SCOPE_SYSTEM_READ = 'system.read';

    const SCOPE_ACCOUNT_READ = 'account.read';

    const SCOPE_LIST_READ = 'list.read';
    const SCOPE_LIST_UPDATE = 'list.update';

    const SCOPE_SUBSCRIBER_READ = 'subscriber.read';
    const SCOPE_SUBSCRIBER_UPDATE = 'subscriber.update';

    const SCOPE_CAMPAIGN_READ = 'campaign.read';
    const SCOPE_CAMPAIGN_UPDATE = 'campaign.update';
    const SCOPE_CAMPAIGN_SCHEDULE = 'campaign.schedule';


    // End Points Production
    const OAUTH_AUTH_URI = 'https://oauth.mailium.net/oauth/authorize';
    const OAUTH_TOKEN_URI = 'https://oauth.mailium.net/oauth/token';
    const OAUTH_REVOKE_URI = 'https://oauth.mailium.net/oauth/revoke';
    const OAUTH_RESOURCE_URI = 'https://oauth.mailium.net/resource';
    const OAUTH_VERIFY_URI = 'https://oauth.mailium.net/verify';


    const EMBEDDED_APP_JS_REDIRECT_CODE = <<<EOR
                    <html>
                        <head>
                            <meta http-equiv="refresh" content="0; url=%authorizationUrl%" />
                        </head>
                        <body>
                            <p><a href="%authorizationUrl%">Click here</a> to authorize this app</p>
                            <script>
                                window.top.location.href = "%authorizationUrl%";
                            </script>
                        </body>
                    </html>
EOR;


    protected $debug;
    protected $logger;
    protected $client;
    protected $config = null;
    protected $scopes = '';
    protected $defaultScope = 'account.read';
    protected $redirectUri = null;
    protected $state = null;
    protected $token = null;
    protected $accessToken = null;
    protected $refreshToken = null;
    protected $resourceOwner = null;
    protected $tokenStoreCallbackFunction = null;
    protected $appType = 'embedded';


    public function __construct($configPath = null, $debug = false)
    {
        if ($configPath) {
            $this->config = json_decode(file_get_contents($configPath));
        } else {
            $this->config = new \stdClass();
            $this->config->client_id = null;
            $this->config->client_secret = null;
            $this->config->scopes = '';
        }
        $this->client = new Client();
        $this->debug = $debug;

        $this->logger = new Logger('OauthClient');

        if ($this->debug === true) {
            $this->logger->pushHandler(new StreamHandler('/tmp/mailiumoauthclient.log', Logger::DEBUG));
        } else {
            $this->logger->pushHandler(new StreamHandler('/tmp/mailiumoauthclient.log', Logger::CRITICAL));
        }
    }

    /** Creates the authorization URL
     * @param null $state , without this parameter a random sting is set for the state parameter.
     * @return string , URL that the client should be redirected to.
     * @throws MailiumOauthClientException
     */
    public function createAuthorizationUrl($state = null)
    {
        $this->logger->debug("creating authorization url");
        if ($this->getClientID() && $this->getClientSecret() && $this->redirectUri) {
            $this->logger->debug("all required values are set: client_id, client_secret, redirect_uri");
            $scopeUrlParam = "scope=" . urlencode($this->getScopes()) . "&";
            return
                static::OAUTH_AUTH_URI
                . "?"
                . "response+type=" . "code" . '&'
                . "client_id=" . $this->getClientID() . '&'
                . $scopeUrlParam
                . "redirect_uri=" . $this->redirectUri . '&'
                . 'state=' . $this->getState()
                ;
        } else {
            $this->logger->debug("not all required values are set: client_id, client_secret, redirect_uri");
            throw MailiumOauthClientException::missingParameter();
        }

    }

    public function createEmbeddedAppHtmlForRedirection($redirectUri)
    {
        return str_replace('%authorizationUrl%', $redirectUri, static::EMBEDDED_APP_JS_REDIRECT_CODE);
    }

    public function setRedirectUri($redirectUri)
    {
        $this->redirectUri = $redirectUri;
    }

    public function getRedirectUri()
    {
        if ($this->redirectUri) {
            return $this->redirectUri;
        }
        return null;
    }

    public function setClientID($clientId)
    {
        $this->config->client_id = $clientId;
    }

    public function getClientID()
    {
        if (isset($this->config->client_id)) {
            return $this->config->client_id;
        }
        return null;

    }

    public function setClientSecret($clientSecret)
    {
        $this->config->client_secret = $clientSecret;
    }

    public function getClientSecret()
    {
        if (isset($this->config->client_secret)) {
            return $this->config->client_secret;
        }
        return null;
    }

    public function setScopes($scopes)
    {
        $this->config->scopes = $scopes;
    }

    public function getScopes()
    {
        if (isset($this->config->scopes) || $this->config->scopes != "") {
            return $this->config->scopes;
        }
        return $this->defaultScope;
    }

    public function addScope($scope)
    {
        $this->config->scopes = $this->config->scopes . ' ' . $scope;
        return $this->config->scopes;

    }

    public function removeScope($scope)
    {
        $this->config->scopes = str_replace($scope, '', $this->config->scopes);
        return $this->config->scopes;

    }

    public function getState()
    {
        if ($this->state){
            return $this->state;
        } else {
            return $this->generateState();
        }
    }

    public function generateState()
    {
        $this->state = bin2hex(openssl_random_pseudo_bytes(32));
        return $this->state;
    }

    public function setToken($token)
    {
        if (is_string($token)) {
            $token = json_decode($token);
            if ($token == null) {
                throw MailiumOauthClientException::canNotDecodeTokenResponse();
            }
        }
        $this->token = $token;
    }

    public function validateOauth($token = null)
    {
        if (is_null($token)) {
            $token = $this->token;
        } else {
            $this->token = $token;
        }
        if (!isset($token->access_token)) {
            return false;
        }
        if (!isset($token->refresh_token)) {
            return false;
        }
        if (isset($token->revoked) && $token->revoked === true)
        {
            return false;
        }

        if ($this->isAccessTokenExpired() === true) {
            try {
                $this->refreshToken();
            } catch (\Exception $e) {
                return false;
            }

            $this->validateOauth();
        }

        return true;
    }
    public function getToken()
    {
        return $this->token;
    }

    public function storeToken()
    {
        $resourceOwner = $this->getResourceOwner();;
        return call_user_func($this->tokenStoreCallbackFunction, $resourceOwner, $this->getToken());
    }

    public function getAccessToken()
    {
        if ($this->token) {
            if (isset($this->token->access_token)) {
                return $this->token->access_token;
            } else {
                return null;
            }

        }
        return null;
    }

    public function getRefreshToken()
    {
        if ($this->token) {
            if (isset($this->token->refresh_token)) {
                return $this->token->refresh_token;
            } else {
                return null;
            }

        }
        return null;
    }

    public function isAccessTokenExpired()
    {
        if ($this->token && isset($this->access_token) && isset($this->refresh_token) ) {
            if (isset($this->token->expires_at)) {
                $expiresAt = (int)$this->token->expires_at;

                return (( $expiresAt - 30) < time());
            }
            return false;
        }
        return false;
    }

    public function setTokenStoreCallbackFunction($callback)
    {
        $this->tokenStoreCallbackFunction = $callback;
    }

    public function authorize($authorizationCode)
    {
        $postArgs = array(
            'code' => $authorizationCode,
            'grant_type' => 'authorization_code',
            'client_id' => $this->config->client_id,
            'client_secret' => $this->config->client_secret,
            'scope' => $this->getScopes(),
            'state' => $this->getState(),
            'redirect_uri' => $this->getRedirectUri(),
        );
        try {
            $response  = $this->client->post(static::OAUTH_TOKEN_URI, [
                'http_errors' => false,
                'headers' =>
                    [
                        'Content-Type' => 'application/json',
                    ],
                'json' => $postArgs,
            ]);

            $responseBody = $response->getBody()->getContents();
            if ($response->getStatusCode() == 200) {
                $this->setToken(json_decode($responseBody));
                $this->token->created_at = time();
                $this->token->expires_at = $this->token->expires_in + time();
                $this->token->revoked = false;
                $this->storeToken();
            } else {
                throw MailiumOauthClientException::remoteErrorDetected($response->getStatusCode(), $responseBody);
            }

        } catch (RequestException $e) {
            echo Psr7\str($e->getRequest());
            if ($e->hasResponse()) {
                echo Psr7\str($e->getResponse());
            }
        }
    }

    /**
     * @throws MailiumOauthClientException
     */
    public function refreshToken()
    {
        $this->logger->debug("refresh the token");
        $postArgs = array(
            'grant_type' => 'refresh_token',
            'client_id' => $this->config->client_id,
            'client_secret' => $this->config->client_secret,
            'refresh_token' => $this->getRefreshToken(),
        );

        $response = $this->client->post(static::OAUTH_TOKEN_URI, [
            'http_errors' => false,
            'headers' =>
                [
                    'Content-Type' => 'application/json',
                ],
            'json' => $postArgs,
        ]);
        $responseBody = $response->getBody()->getContents();
        $responseBodyAsObject = json_decode($responseBody);
        if ($response->getStatusCode() == 200) {
            $this->setToken(json_decode($responseBody));
            $this->token->created_at = time();
            $this->token->expires_at = $this->token->expires_in + time();
            $this->token->revoked = false;
            $this->storeToken();
        } else if (isset($responseBodyAsObject->error) &&  $responseBodyAsObject->error == MailiumOauthClientException::INVALID_REQUEST_ERROR_TYPE) {
            $this->setToken(new \stdClass());
            $this->storeToken();
            return false;
        } else if (isset($responseBodyAsObject->error) &&  $responseBodyAsObject->error == MailiumOauthClientException::ACCESS_DENIED_ERROR_TYPE) {
            $this->setToken(new \stdClass());
            $this->storeToken();
            return false;
        } else {
            $this->setToken(new \stdClass());
            $this->storeToken();
            return false;
        }
    }

    /** Retrieve the resource owner details
     * @return mixed
     * @throws MailiumOauthClientException
     */

    public function getResourceOwner()
    {
        $accessToken = $this->getAccessToken();
        $response = $this->client->get(static::OAUTH_RESOURCE_URI, array(
            'http_errors' => false,
            'headers' =>
                array(
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . $accessToken,
                )
        ));
        $responseBody = $response->getBody()->getContents();
        $responseBodyAsObject = json_decode($responseBody);
        if ($response->getStatusCode() == 200) {
            return $responseBodyAsObject;
        } else if (isset($responseBodyAsObject->error)) {
            return false;
        } else {
            $this->logger->debug("Unexpected non-200 response without error type received, status code : " . $response->getStatusCode());
            return false;
        }
    }

    public function verifyToken($accessToken)
    {
        if ($accessToken == '') {
            return false;
        }
        $result = $this->getResourceOwner();

        if (isset($result->acc_id)) {
            return true;
        }
        return false;
    }

    /** Retrieve the resource owner details (first checks the cached response)
     * @return mixed
     * @throws MailiumOauthClientException
     */

    public function getResourceOwnerCached()
    {
        if ($this->resourceOwner) {
            return $this->resourceOwner;
        } else {
            return $this->resourceOwner = $this->getResourceOwner();
        }
    }

    public function getAppType()
    {
        return $this->appType;
    }

    public function setAppType($appType)
    {
        $this->appType = $appType;
    }

    public static function verifyHmac ($data, $hmacKey)
    {
        return Hmac::verifyHmac($data, $hmacKey);
    }

}
