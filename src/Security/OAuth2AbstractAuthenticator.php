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

use BeyondBlueSky\OAuth2PKCEClient\Entity\OAuth2Session;

use BeyondBlueSky\LibJWT\Entity\JWToken;
use BeyondBlueSky\LibJWT\DependencyInjection\JWTServiceExtension as JWTService;

use BeyondBlueSky\OAuth2PKCEClient\DependencyInjection\OAuth2PKCEClientExtension as OAuth2PKCEClient;

abstract class OAuth2AbstractAuthenticator extends AbstractGuardAuthenticator {
    
    /**
     *
     * @var EntityManagerInterface
     */
    protected $em;
    
    /**
     *
     * @var OAuth2PKCEClient
     */
    protected $oauth;
    
    /**
     *
     * @var JWTService
     */
    protected $jwt;

    protected $sessionRepo;
    
    public function __construct(OAuth2PKCEClient $oauth, EntityManagerInterface $em, JWTService $jwt)
    {
        $this->em = $em;
        $this->oauth = $oauth;
        $this->jwt = $jwt;
        $this->sessionRepo = $this->oauth->getSessionRepository();  
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
    
    /**
     * Protected function that asks for an access token
     * 
     * @param OAuth2Session $session
     * @param string $code
     * @return type
     * @throws NoAuthCodeAuthenticationException
     * @throws IdentityProviderAuthenticationException
     * @throws InvalidStateAuthenticationException
     */
    public function fetchAccessToken(OAuth2Session $session, string $code)
    {
        try {
            return $this->oauth->getToken($session->getState(), $session->getCodeVerifier(), $code );
        } catch (MissingAuthorizationCodeException $e) {
            throw new NoAuthCodeAuthenticationException();
        } catch (IdentityProviderException $e) {
            throw new IdentityProviderAuthenticationException($e);
        } catch (InvalidStateException $e) {
            throw new InvalidStateAuthenticationException($e);
        }
    }
    
    public function fetchUser(\StdClass $credentials){
        
        return $this->getOwner($credentials->access_token);
        
    }
    
    public function fetchTenant(\StdClass $credentials){
        
        return $this->getOwnTenant($credentials->access_token);
        
    }
    
    private function getOwner(string $accessToken): \stdClass {
        $response = $this->oauth->getOwner($accessToken);
        
        $session = $this->sessionRepo->findOneBy(['accessToken'=> $accessToken]);
        if( $session && $response ){
            $session->setUserId($response->login);
            $this->em->flush();
        }
        
        return $response;
        //return $this->oauth->getOwner($accessToken);
    }
    
    private function getOwnTenant(string $accessToken): \stdClass {
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
    
    public function decodeJWT(string $token): JWToken {
        return $this->jwt->decode($token);
    }

    private function getMyHost(Request $request): string {
        return $request->getScheme() . '://' . $request->getHttpHost();
    }
        
}