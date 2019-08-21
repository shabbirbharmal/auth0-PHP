<?php

namespace Auth0\SDK\Helpers;

use Auth0\SDK\API\Helpers\RequestBuilder;
use Auth0\SDK\Helpers\Cache\CacheHandler;
use Auth0\SDK\Helpers\Cache\NoCacheHandler;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ClientException;

/**
 * Class JwksFetcher.
 *
 * @package Auth0\SDK\Helpers
 */
class JwksFetcher
{

    private $jwks_url;

    private $cache;

    private $guzzleOptions;

    public function __construct($jwks_url, CacheHandler $cache, array $guzzleOptions = [])
    {
        $this->jwks_url      = $jwks_url;
        $this->cache         = $cache;
        $this->guzzleOptions = $guzzleOptions;
    }

    /**
     * Fetch a JWKS.
     *
     * @return array
     */
    public function get()
    {
        $keys = $this->cache->get($this->jwks_url);
        if (! is_null($keys)) {
            return $keys;
        }

        $jwks = $this->requestJwks();

        if (empty( $jwks ) || empty( $jwks['keys'] )) {
            return [];
        }

        $keys = [];
        foreach ($jwks['keys'] as $key) {
            if (empty( $key['kid'] ) || empty( $key['x5c'] )) {
                continue;
            }

            $keys[$key['kid']] = $this->convertCertToPem( $key['x5c'] );
        }

        return $keys;
    }

    /**
     * Get a JWKS from a specific URL.
     *
     * @return mixed|string
     *
     * @throws RequestException If $jwks_url is empty or malformed.
     * @throws ClientException  If the JWKS cannot be retrieved.
     *
     * @codeCoverageIgnore
     */
    protected function requestJwks()
    {
        $request = new RequestBuilder([
            'domain' => $this->jwks_url,
            'method' => 'GET',
            'guzzleOptions' => $this->guzzleOptions
        ]);
        return $request->call();
    }

    /**
     * Convert a certificate to PEM format.
     *
     * @param string $cert X509 certificate to convert to PEM format.
     *
     * @return string
     */
    protected function convertCertToPem($cert)
    {
        $output  = '-----BEGIN CERTIFICATE-----'.PHP_EOL;
        $output .= chunk_split($cert, 64, PHP_EOL);
        $output .= '-----END CERTIFICATE-----'.PHP_EOL;
        return $output;
    }
}
