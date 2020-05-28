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
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

use BeyondBlueSky\OAuth2PKCEClient\DependencyInjection\OAuth2PKCEClientExtension as OAuth2PKCEClient;

use BeyondBlueSky\LibJWT\Entity\JWToken;
use BeyondBlueSky\LibJWT\DependencyInjection\JWTServiceExtension as JWTService;

abstract class OAuth2ApiAuthenticator extends AbstractGuardAuthenticator
{
    protected $em;
    private $oauth;
    private $log;
    private $jwt;

    public function __construct(EntityManagerInterface $em, OAuth2PKCEClient $oauth, JWTService $jwt) //,LoggerInterface $log )
    {
        $this->em = $em;
        $this->oauth = $oauth;
        //$this->log = $log;
        $this->jwt = $jwt;
    }

    /**
     * Called on every request to decide if this authenticator should be
     * used for the request. Returning `false` will cause this authenticator
     * to be skipped.
     */
    public function supports(Request $request)
    {
        $result = $request->headers->has('AUTHORIZATION');
        
        $resStr = ($result)?'true':'false';
        $headers= json_encode($request->headers->all());
        //$this->log->info("ApiAuthenticator::supports() "); //.$headers );
        
        return $result;
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
    
    public abstract function getUser($credentials, UserProviderInterface $userProvider);

    public function checkCredentials($credentials, UserInterface $user)
    {
        // Check credentials - e.g. make sure the password is valid.
        // In case of an API token, no credential check is needed.

        // Return `true` to cause authentication success
        return true;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        // on success, let the request continue
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $data = [
            // you may want to customize or obfuscate the message first
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData())

            // or to translate this message
            // $this->translator->trans($exception->getMessageKey(), $exception->getMessageData())
        ];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    /**
     * Called when authentication is needed, but it's not sent
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $data = [
            // you might translate this message
            'message' => 'Authentication Required'
        ];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    public function supportsRememberMe()
    {
        return false;
    }
    
    private function getMyHost(Request $request): string {
        return $request->getScheme() . '://' . $request->getHttpHost();
    }
    

}