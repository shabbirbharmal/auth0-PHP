<?php
namespace Auth0\Tests\Api\Helpers;

use Auth0\SDK\JWTVerifier;
use Auth0\SDK\Exception\InvalidTokenException;
use Auth0\Tests\Traits\ErrorHelpers;
use Auth0\SDK\Helpers\JWKFetcher;
use Firebase\JWT\JWT;

/**
 * Class JWTVerifierTest
 *
 * @package Auth0\Tests\Api\Helpers
 */
class JWTVerifierTest extends \PHPUnit_Framework_TestCase
{
    use ErrorHelpers;

    public function testThatTokenMissingExpFails()
    {
        $verifier    = $this->getJwtVerifier();
        $jwt_payload = [ 'sub' => uniqid() ];
        $jwt         = JWT::encode( $jwt_payload, '__client_secret__', 'HS256' );

        try {
            $err_msg = 'No error';
            $verifier->verifyAndDecode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Missing token exp', $err_msg, $err_msg );
    }

    public function testThatTokenMissingIatFails()
    {
        $verifier    = $this->getJwtVerifier();
        $jwt_payload = [
            'sub' => uniqid(),
            'exp' => time() + 10,
        ];
        $jwt         = JWT::encode( $jwt_payload, '__client_secret__', 'HS256' );

        try {
            $err_msg = 'No error';
            $verifier->verifyAndDecode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Missing token iat', $err_msg, $err_msg );
    }

    public function testThatTokenMissingIssFails()
    {
        $verifier    = $this->getJwtVerifier();
        $jwt_payload = [
            'sub' => uniqid(),
            'exp' => time() + 10,
            'iat' => 1,
        ];
        $jwt         = JWT::encode( $jwt_payload, '__client_secret__', 'HS256' );

        try {
            $err_msg = 'No error';
            $verifier->verifyAndDecode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Missing token iss', $err_msg, $err_msg );
    }

    public function testThatTokenInvalidIssFails()
    {
        $verifier    = $this->getJwtVerifier();
        $jwt_payload = [
            'sub' => uniqid(),
            'exp' => time() + 10,
            'iat' => 1,
            'iss' => '__invalid_issuer__',
        ];
        $jwt         = JWT::encode( $jwt_payload, '__client_secret__', 'HS256' );

        try {
            $err_msg = 'No error';
            $verifier->verifyAndDecode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Invalid token iss', $err_msg, $err_msg );
    }

    public function testThatTokenMissingAudienceFails()
    {
        $verifier    = $this->getJwtVerifier();
        $jwt_payload = [
            'sub' => uniqid(),
            'exp' => time() + 10,
            'iat' => 1,
            'iss' => '__valid_issuer__',
        ];
        $jwt         = JWT::encode( $jwt_payload, '__client_secret__', 'HS256' );

        try {
            $err_msg = 'No error';
            $verifier->verifyAndDecode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Missing token aud', $err_msg, $err_msg );
    }

    public function testThatTokenInvalidAudienceFails()
    {
        $verifier    = $this->getJwtVerifier();
        $jwt_payload = [
            'sub' => uniqid(),
            'exp' => time() + 10,
            'iat' => 1,
            'iss' => '__valid_issuer__',
            'aud' => '__invalid_audience__',
        ];
        $jwt         = JWT::encode( $jwt_payload, '__client_secret__', 'HS256' );

        try {
            $err_msg = 'No error';
            $verifier->verifyAndDecode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Invalid token aud', $err_msg, $err_msg );
    }

    public function testThatTokenMissingAzpFails()
    {
        $verifier    = $this->getJwtVerifier();
        $jwt_payload = [
            'sub' => uniqid(),
            'exp' => time() + 10,
            'iat' => 1,
            'iss' => '__valid_issuer__',
            'aud' => [ '__valid_audience_1__', '__valid_audience_2__' ],
        ];
        $jwt         = JWT::encode( $jwt_payload, '__client_secret__', 'HS256' );

        try {
            $err_msg = 'No error';
            $verifier->verifyAndDecode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Missing token azp', $err_msg, $err_msg );
    }

    private function getJwtVerifier()
    {
        return new JWTVerifier( [
            'valid_audiences' => [ '__valid_audience_1__' ],
            'authorized_iss' => [ '__valid_issuer__' ],
            'supported_algs' => [ 'HS256' ],
            'client_secret' => '__client_secret__',
            'secret_base64_encoded' => false,
        ] );
    }
}
