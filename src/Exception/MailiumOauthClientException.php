<?php namespace MailiumOauthClient\Exception;


class MailiumOauthClientException extends \Exception
{
    // Authorization Server Error Codes
    const UNSUPPORTED_GRANT_TYPE = 2;
    const INVALID_REQUEST = 3;
    const INVALID_CLIENT = 4;
    const INVALID_SCOPE = 5;
    const INVALID_CREDENTIALS = 6;
    const SERVER_ERROR = 7;
    const INVALID_REFRESH_TOKEN = 8;
    const ACCESS_DENIED = 9;

    // Local Error Codes
    const REQUIRED_PARAMETER_MISSING = 22;
    const INVALID_TOKEN_FORMAT = 23;
    const TOKEN_IS_NOT_SET = 25;
    const TOKEN_EXPIRED = 26;

    // Authorization Server Error Types
    const UNSUPPORTED_GRANT_TYPE_ERROR_TYPE = 'unsupported_grant_type';
    const INVALID_REQUEST_ERROR_TYPE = 'invalid_request';
    const INVALID_CLIENT_ERROR_TYPE = 'invalid_client';
    const INVALID_SCOPE_ERROR_TYPE = 'invalid_scope';
    const INVALID_CREDENTIALS_ERROR_TYPE = 'invalid_credentials';
    const SERVER_ERROR_ERROR_TYPE = 'server_error';
    const INVALID_REFRESH_TOKEN_ERROR_TYPE = 'invalid_request';
    const ACCESS_DENIED_ERROR_TYPE = 'access_denied';


    public function __construct($message, $code, \Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    public static function missingParameter()
    {
        $errorMessage = 'A required parameter is missing';

        return new static($errorMessage, static::REQUIRED_PARAMETER_MISSING);
    }

    public static function canNotDecodeTokenResponse()
    {
        $errorMessage = 'Can not decode token response';

        return new static($errorMessage, static::INVALID_TOKEN_FORMAT);
    }

    public static function remoteErrorDetected($statusCode, $rawBody)
    {
        $body = json_decode($rawBody, true);

        $remoteErrorType = isset($body['error']) ? $body['error'] : "";
        $remoteErrorCode = isset($body['error_code']) ? $body['error_code'] : 0;
        $remoteErrorMessage = isset($body['message']) ? $body['message'] : "";
        $remoteErrorHint = isset($body['hint']) ? $body['hint'] : "";


        $errorMessage = "Status Code: " . $statusCode . " / " . "Error Type: " . $remoteErrorType . " / " . "Error Code: " .  $remoteErrorCode . " / " . "Message: " . $remoteErrorMessage . " / " . "Hint: " . $remoteErrorHint;
        $errorCode = (int)$remoteErrorCode;


        return new static($errorMessage, $errorCode);
    }

    public static function canNotRefreshOauthTokens($errorType)
    {
        $errorMessage = "Can not refresh oauth tokens, received : " . (string)$errorType;

        return new static($errorMessage, static::TOKEN_IS_NOT_SET);

    }
    public static function tokenIsNotSet()
    {
        $errorMessage = 'Token is not set';

        return new static($errorMessage, static::TOKEN_IS_NOT_SET);
    }

    public static function tokenIsExpired()
    {
        $errorMessage = 'Access token expired';

        return new static($errorMessage, static::TOKEN_EXPIRED);
    }

}