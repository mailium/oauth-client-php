<?php namespace MailiumOauthClient;

class Hmac
{
    public static function generateHmac ($data, $hmacKey)
    {
        // if data is an array we need to escape it.
        if (is_array($data)) {
            // Convert the query string to an array
            $queryString = http_build_query($data);
        } else {
            $queryString = $data;
        }
        parse_str($queryString, $dataMap);

        $hmacMap = array();
        foreach ($dataMap as $dataKey => $dataValue) {

            $key = str_replace('%', '%25', $dataKey);
            $value =str_replace('%', '%25', $dataValue);

            $key =str_replace('&', '%26', $key);
            $value =str_replace('&', '%26', $value);

            $key =str_replace('=', '%3D', $key);

            $hmacMap[$key] = $value;
        }

        // Add timestamp
        $timeStamp = time();
        $hmacMap['timestamp'] = $timeStamp;
        // Sort the array map
        ksort($hmacMap);

        $hmacString = http_build_query($hmacMap);

        $digest = hash_hmac('sha256', $hmacString, $hmacKey);

        return array(
            'data' => $hmacString,
            'timestamp' => $timeStamp,
            'hmac' => $digest,
            'query_string' => $hmacString . '&' . 'hmac=' . $digest
        );
    }

    public static function verifyHmac ($data, $hmacKey)
    {

        if (is_array($data)) {
            // Convert the query string to an array
            $queryString = http_build_query($data);
        } else {
            $queryString = $data;
        }

        parse_str($queryString, $dataMap);

        $hmacMap = array();
        foreach ($dataMap as $dataKey => $dataValue) {
            $key = str_replace('%', '%25', $dataKey);
            $value =str_replace('%', '%25', $dataValue);

            $key =str_replace('&', '%26', $key);
            $value =str_replace('&', '%26', $value);

            $key =str_replace('=', '%3D', $key);

            $hmacMap[$key] = $value;
        }

        $hmacFromRequest = $hmacMap['hmac'];
        unset($hmacMap['hmac']);

        // Sort the array map
        ksort($hmacMap);

        $hmacString = http_build_query($hmacMap);

        $digest = hash_hmac('sha256', $hmacString, $hmacKey);

        return $hmacFromRequest === $digest;
    }

}
