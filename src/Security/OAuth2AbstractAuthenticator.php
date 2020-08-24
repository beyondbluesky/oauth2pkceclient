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

use BeyondBlueSky\OAuth2PKCEClient\Entity\Exception\FailedSignatureException;

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
        $auth = $request->headers->get('AUTHORIZATION');
        if( $auth == null ){
            $auth = $request->headers->get('AUTHORIZATION2');           
        }
        
        $method = $request->getMethod();
        if( $method == 'GET') {
            $headers = $request->server->all();
            $queryStr= $headers['QUERY_STRING'];
            $queryArray = explode('&', $queryStr);
            foreach($queryArray as $q){
                $keypair = explode('=', $q);
                if( sizeof($keypair) > 1 && $keypair[0] == '_method'){
                    $method = $keypair[1];
                }
            }
        }else if( $method == 'POST'){
            // It could be an advance method. We look for it
            $body = $request->getContent();
            $content = json_decode($body);
            if( isset($content->_method)){
                $method = $content->_method;
            }
        }
        
        $out= [
            'authorization'=> $auth,
            'uri'=> $request->getRequestUri(),
            'host'=> $this->getMyHost($request),
            'method'=> $method,
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
    
    public function getOwner(string $accessToken): \stdClass {
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
        
        if ( $token === null ) {
            // The token header was empty, authentication fails with HTTP Status
            // Code 401 "Unauthorized"
            throw new CustomUserMessageAuthenticationException(
                '401-001 Missing token'
            );
        }

        // We check if the token is signed and if the token match the signature of our OAuth server
        if( $this->jwt->signedToken($token) && ! $this->jwt->tokenVerified($token, $this->oauth->getServerCert() )) {
            throw new FailedSignatureException('Token has wrong signature.');
        }
        $jwToken = $this->jwt->decode($token);
        
        if( $jwToken->isExpired() ){
            // The token header was empty, authentication fails with HTTP Status
            // Code 401 "Unauthorized"
            throw new CustomUserMessageAuthenticationException(
                '401-002 Token expired'
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
    
    public function checkJWT(string $token ): bool {
        
        if( ! $this->jwt->signedToken($token) ){
            
            throw new FailedSignatureException('Token has no signature.');
        }   
        
        if( ! $this->jwt->tokenVerified($token, $this->oauth->getServerCert() ) ) {
            
            throw new FailedSignatureException('Token has wrong signature.');
        }
        
        
        return true;
    }
        
}