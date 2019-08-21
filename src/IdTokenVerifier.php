<?php

namespace Auth0\SDK;

use Auth0\SDK\Exception\CoreException;
use Auth0\SDK\Exception\InvalidTokenException;

use Auth0\SDK\Helpers\JwksFetcher;
use Firebase\JWT\JWT;

/**
 * Class IdTokenVerifier.
 * Used to validate ID tokens issued by Auth0.
 *
 * @package Auth0\SDK
 */
class IdTokenVerifier
{

    /**
     * @var string
     */
    protected $algorithm;

    /**
     * @var string
     */
    protected $signature_key;

    /**
     * @var null|JwksFetcher
     */
    protected $jwks_fetcher;

    /**
     * @var string
     */
    protected $client_id;

    /**
     * @var string
     */
    protected $issuer;

    /**
     * IdTokenVerifier constructor.
     *
     * @param  array            $config
     * @param  JwksFetcher|null $jwks_fetcher
     * @throws CoreException
     */
    public function __construct(array $config, $jwks_fetcher = null)
    {
        // Token algorithm to verify signature.
        if (empty( $config['algorithm'] ) || ! in_array( $config['algorithm'], [ 'HS256', 'RS256' ] )) {
            throw new CoreException('Config key "algorithm" is required to be HS256 or RS256');
        }

        $this->algorithm = (string) $config['algorithm'];

        // Need a signature key or JwksFetcher to verify token signature.
        if (empty( $config['signature_key'] ) && ! $jwks_fetcher instanceof JwksFetcher) {
            throw new CoreException('Config key "signature_key" is required if no JwksFetcher is provided');
        }

        $this->signature_key = (string) $config['signature_key'];
        $this->jwks_fetcher  = $jwks_fetcher;

        // Client ID to validate aud and azp claim.
        if (empty( $config['client_id'] )) {
            throw new CoreException('Config key "client_id" is required');
        }

        $this->client_id = (string) $config['client_id'];

        // Issuer to validate where the token came from.
        if (empty( $config['issuer'] )) {
            throw new CoreException('Config key "issuer" is required');
        }

        $this->issuer = (string) $config['issuer'];
    }


    /**
     * @param  $jwt
     * @return mixed
     * @throws InvalidTokenException
     */
    public function decode($jwt)
    {
        try {
            $key     = $this->signature_key ? $this->signature_key : $this->jwks_fetcher->get();
            $jwt_obj = $this->decodeToken($jwt, $key);
        } catch (\Exception $e) {
            throw new InvalidTokenException($e->getMessage());
        }

        // Check if expiration is missing.
        if (empty( $jwt_obj->exp )) {
            throw new InvalidTokenException( 'Missing token exp' );
        }

        // Check if issued-at is missing.
        if (empty( $jwt_obj->iat )) {
            throw new InvalidTokenException( 'Missing token iat' );
        }

        // Check if issuer is missing.
        if (empty( $jwt_obj->iss ) || $jwt_obj->iss !== $this->issuer) {
            throw new InvalidTokenException('Invalid token iss');
        }

        // Check if audience is missing.
        if (empty( $jwt_obj->aud )) {
            throw new InvalidTokenException( 'Missing token aud' );
        }

        // Check if the token audience is allowed.
        $token_aud = is_array($jwt_obj->aud) ? $jwt_obj->aud : [$jwt_obj->aud];
        if (! in_array($this->client_id, $token_aud)) {
            throw new InvalidTokenException( 'Invalid token aud' );
        }

        // Check token azp value if token contains multiple audiences.
        if (count( $token_aud ) > 1 && (empty( $jwt_obj->azp ) || $jwt_obj->azp !== $this->client_id)) {
            throw new InvalidTokenException( 'Invalid token azp' );
        }

        return $jwt_obj;
    }

    /**
     * Wrapper for JWT::decode().
     *
     * @param string       $jwt    JWT to decode.
     * @param string|array $secret Secret to use.
     *
     * @return mixed
     *
     * @codeCoverageIgnore
     */
    protected function decodeToken($jwt, $secret)
    {
        return JWT::decode( $jwt, $secret, [ $this->algorithm ] );
    }
}
