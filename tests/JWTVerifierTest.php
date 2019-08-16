<?php
namespace Auth0\Tests\Api\Helpers;

use Auth0\SDK\API\Helpers\TokenGenerator;
use Auth0\SDK\JWTVerifier;
use Auth0\SDK\Auth0JWT;
use Auth0\SDK\Exception\CoreException;
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

    public function testThatTokenMissingAudienceFails()
    {
        $verifier = new JWTVerifier( [
            'valid_audiences' => [ '__valid_audience__' ],
            'supported_algs' => [ 'HS256' ],
            'client_secret' => '__client_secret__',
            'secret_base64_encoded' => false,
        ] );

        $jwt_payload = [ 'sub' => uniqid() ];
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
        $verifier = new JWTVerifier( [
            'valid_audiences' => [ '__valid_audience__' ],
            'supported_algs' => [ 'HS256' ],
            'client_secret' => '__client_secret__',
            'secret_base64_encoded' => false,
        ] );

        $jwt_payload = [
            'sub' => uniqid(),
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
        $verifier = new JWTVerifier( [
            'valid_audiences' => [ '__valid_audience_1__' ],
            'supported_algs' => [ 'HS256' ],
            'client_secret' => '__client_secret__',
            'secret_base64_encoded' => false,
        ] );

        $jwt_payload = [
            'sub' => uniqid(),
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
}
