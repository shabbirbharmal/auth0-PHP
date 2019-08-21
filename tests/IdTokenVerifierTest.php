<?php
namespace Auth0\Tests\Api\Helpers;

use Auth0\SDK\IdTokenVerifier;
use Auth0\SDK\Exception\CoreException;
use Auth0\SDK\Exception\InvalidTokenException;

use Firebase\JWT\JWT;

/**
 * Class IdTokenVerifierTest
 *
 * @package Auth0\Tests\Api\Helpers
 */
class IdTokenVerifierTest extends \PHPUnit_Framework_TestCase
{

    private $verifierConfig = [
        'algorithm' => 'HS256',
        'signature_key' => '__client_secret__',
        'client_id' => '__client_id__',
        'issuer' => '__valid_issuer__',
    ];

    public function testThatConstructorRejectsEmptyAlg()
    {
        try {
            $err_msg = 'No error';
            new IdTokenVerifier( [] );
        } catch (CoreException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Config key "algorithm" is required', $err_msg, $err_msg );
    }

    public function testThatConstructorRejectsInvalidAlg()
    {
        try {
            $err_msg = 'No error';
            new IdTokenVerifier( [ 'algorithm' => 'None' ] );
        } catch (CoreException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Config key "algorithm" is required to be HS256 or RS256', $err_msg, $err_msg );
    }

    public function testThatConstructorRejectsEmptyKey()
    {
        try {
            $err_msg = 'No error';
            new IdTokenVerifier( [ 'algorithm' => 'HS256' ] );
        } catch (CoreException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Config key "signature_key" is required', $err_msg, $err_msg );
    }

    public function testThatConstructorRejectsEmptyClientId()
    {
        try {
            $err_msg = 'No error';
            new IdTokenVerifier( [ 'algorithm' => 'HS256', 'signature_key' => uniqid() ] );
        } catch (CoreException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Config key "client_id" is required', $err_msg, $err_msg );
    }

    public function testThatConstructorRejectsEmptyIssuer()
    {
        try {
            $err_msg = 'No error';
            new IdTokenVerifier( [ 'algorithm' => 'HS256', 'signature_key' => uniqid(), 'client_id' => uniqid() ] );
        } catch (CoreException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Config key "issuer" is required', $err_msg, $err_msg );
    }

    public function testThatTokenMissingExpFails()
    {
        $verifier    = new IdTokenVerifier( $this->verifierConfig );
        $jwt_payload = [ 'sub' => uniqid() ];
        $jwt         = JWT::encode( $jwt_payload, '__client_secret__', 'HS256' );

        try {
            $err_msg = 'No error';
            $verifier->decode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Missing token exp', $err_msg, $err_msg );
    }

    public function testThatTokenMissingIatFails()
    {
        $verifier    = new IdTokenVerifier( $this->verifierConfig );
        $jwt_payload = [
            'sub' => uniqid(),
            'exp' => time() + 10,
        ];
        $jwt         = JWT::encode( $jwt_payload, '__client_secret__', 'HS256' );

        try {
            $err_msg = 'No error';
            $verifier->decode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Missing token iat', $err_msg, $err_msg );
    }

    public function testThatTokenMissingIssFails()
    {
        $verifier    = new IdTokenVerifier( $this->verifierConfig );
        $jwt_payload = [
            'sub' => uniqid(),
            'exp' => time() + 10,
            'iat' => 1,
        ];
        $jwt         = JWT::encode( $jwt_payload, '__client_secret__', 'HS256' );

        try {
            $err_msg = 'No error';
            $verifier->decode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Invalid token iss', $err_msg, $err_msg );
    }

    public function testThatTokenInvalidIssFails()
    {
        $verifier    = new IdTokenVerifier( $this->verifierConfig );
        $jwt_payload = [
            'sub' => uniqid(),
            'exp' => time() + 10,
            'iat' => 1,
            'iss' => '__invalid_issuer__',
        ];
        $jwt         = JWT::encode( $jwt_payload, '__client_secret__', 'HS256' );

        try {
            $err_msg = 'No error';
            $verifier->decode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Invalid token iss', $err_msg, $err_msg );
    }

    public function testThatTokenMissingAudienceFails()
    {
        $verifier    = new IdTokenVerifier( $this->verifierConfig );
        $jwt_payload = [
            'sub' => uniqid(),
            'exp' => time() + 10,
            'iat' => 1,
            'iss' => '__valid_issuer__',
        ];
        $jwt         = JWT::encode( $jwt_payload, '__client_secret__', 'HS256' );

        try {
            $err_msg = 'No error';
            $verifier->decode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Missing token aud', $err_msg, $err_msg );
    }

    public function testThatTokenInvalidAudienceFails()
    {
        $verifier    = new IdTokenVerifier( $this->verifierConfig );
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
            $verifier->decode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Invalid token aud', $err_msg, $err_msg );
    }

    public function testThatTokenMissingAzpFails()
    {
        $verifier    = new IdTokenVerifier( $this->verifierConfig );
        $jwt_payload = [
            'sub' => uniqid(),
            'exp' => time() + 10,
            'iat' => 1,
            'iss' => '__valid_issuer__',
            'aud' => [ '__client_id__', '__valid_audience_2__' ],
        ];
        $jwt         = JWT::encode( $jwt_payload, '__client_secret__', 'HS256' );

        try {
            $err_msg = 'No error';
            $verifier->decode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Invalid token azp', $err_msg, $err_msg );
    }

    public function testThatTokenInvalidAzpFails()
    {
        $verifier    = new IdTokenVerifier( $this->verifierConfig );
        $jwt_payload = [
            'sub' => uniqid(),
            'exp' => time() + 10,
            'iat' => 1,
            'iss' => '__valid_issuer__',
            'aud' => [ '__client_id__', '__valid_audience_2__' ],
            'azp' => '__invalid_azp__',
        ];
        $jwt         = JWT::encode( $jwt_payload, '__client_secret__', 'HS256' );

        try {
            $err_msg = 'No error';
            $verifier->decode( $jwt );
        } catch (InvalidTokenException $e) {
            $err_msg = $e->getMessage();
        }

        $this->assertStringStartsWith( 'Invalid token azp', $err_msg, $err_msg );
    }
}
