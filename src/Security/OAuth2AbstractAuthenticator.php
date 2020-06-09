<?php
/* 
 *  The Creative Commons BY-NC-SA 4.0 License
 *  Attribution-NonCommercial-ShareAlike 4.0 International
 * 
 *  Josep Llauradó Selvas
 *  pep@beyondbluesky.com
 * 
 *  For the full copyright and license information, please view the LICENSE
 *  file that was distributed with this source code.
 */

namespace BeyondBlueSky\OAuth2PKCEClient\Security;

use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;

use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

use BeyondBlueSky\LibJWT\Entity\JWToken;
use BeyondBlueSky\LibJWT\DependencyInjection\JWTServiceExtension as JWTService;

use BeyondBlueSky\OAuth2PKCEClient\DependencyInjection\OAuth2PKCEClientExtension as OAuth2PKCEClient;

abstract class OAuth2AbstractAuthenticator extends AbstractGuardAuthenticator {
    
    protected $em;
    private $oauth;
    private $log;
    private $jwt;

    public function __construct(EntityManagerInterface $em, OAuth2PKCEClient $oauth, JWTService $jwt)
    {
        $this->em = $em;
        $this->oauth = $oauth;
        $this->jwt = $jwt;
    }

    /**
     * Called on every request. Return whatever credentials you want to
     * be passed to getUser() as $credentials.
     */
    public function getCredentials(Request $request)
    {
        $out= [
            'authorization'=>$request->headers->get('AUTHORIZATION'),
            'uri'=> $request->getRequestUri(),
            'host'=> $this->getMyHost($request),
            'method'=> $request->getMethod(),
            ];
        
        //$this->log->info("ApiAuthenticator::getCredentials() ".json_encode($out));
        
        return $out;
    }

    public function getAccessToken($credentials): string {
        if( ! isset($credentials['authorization'])){
            throw new CustomUserMessageAuthenticationException(
                'Missing token'
            );
        }        
        $authArray = explode(' ', $credentials['authorization']);
        if( sizeof($authArray) < 2 ){
            throw new CustomUserMessageAuthenticationException(
                'Missing token'
            );
        }
        $token = $authArray[1];

        
        return $token;
    }
    
    public function getOwner(string $accessToken): \stdClass {
        return $this->oauth->getOwner($accessToken);
    }
    
    public function getOwnTenant(string $accessToken): \stdClass {
        return $this->oauth->getOwnTenant($accessToken);
    }
    
    public function getJWToken($credentials): ?JWToken {
        
        $token= $this->getAccessToken($credentials);
        
        if (null === $token) {
            // The token header was empty, authentication fails with HTTP Status
            // Code 401 "Unauthorized"
            throw new CustomUserMessageAuthenticationException(
                'Missing token'
            );
        }

        $jwToken = $this->jwt->decode($token);
        
        if( $jwToken->isExpired() ){
            // The token header was empty, authentication fails with HTTP Status
            // Code 401 "Unauthorized"
            throw new CustomUserMessageAuthenticationException(
                'Token expired'
            );
        }
        
        return $jwToken;
    }

    public function checkClaims($credentials): bool {
        $target = $credentials['host']. $credentials['uri'];
        $jwt = $this->getJWToken($credentials);
        
        $isAllowed = $this->jwt->inClaims($jwt, $target, $credentials['method']);

        return $isAllowed;
    }
    

}