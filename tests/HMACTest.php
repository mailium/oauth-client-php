<?php
use PHPUnit\Framework\TestCase;
use MailiumOauthClient\Hmac;

class HmacTest extends PHPUnit_Framework_TestCase
{
    const KEY = 'verysecretveryhushhush';
    /**
     * A basic test example.
     *
     * @return void
     */
    public function testHmacGenerationUsingStringAndVerification()
    {
        $queryString = 'accid=test-customer.mailium.net';

        $generateHmacResult = Hmac::generateHmac($queryString, static::KEY);
        echo (print_r($generateHmacResult));

        $hmacVerificationResult = Hmac::verifyHmac($generateHmacResult['query_string'], static::KEY);

        $this->assertTrue($hmacVerificationResult);
    }

    public function testHmacGenerationUsingArrayAndVerification()
    {
        $queryArray = array(
            'accid' => 'test-customer.mailium.net',
        );

        $generateHmacResult = Hmac::generateHmac($queryArray, static::KEY);
        echo (print_r($generateHmacResult));

        $hmacVerificationResult = Hmac::verifyHmac($generateHmacResult['query_string'], static::KEY);

        $this->assertTrue($hmacVerificationResult);
    }
}
