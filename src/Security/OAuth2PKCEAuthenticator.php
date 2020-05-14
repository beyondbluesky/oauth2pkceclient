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

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

use BeyondBlueSky\OAuth2PKCEClient\Entity\User;
use BeyondBlueSky\OAuth2PKCEClient\Entity\OAuth2Session;

use BeyondBlueSky\OAuth2PKCEClient\Repository\OAuth2SessionRepository;
use BeyondBlueSky\OAuth2PKCEClient\DependencyInjection\OAuth2PKCEClientExtension as OAuth2PKCEClient;

/**
 * Abstrct class that has to implement 2 basic methods in order to authenticate 
 * via OAuth2:
 * 
 *  - supports(): Validates that the path for the remote auth call to start authentication is correct.
 *  - getUser():  Called by the redirectUri to fetch the access token and user authenticated.
 */
abstract class OAuth2PKCEAuthenticator extends AbstractGuardAuthenticator
{
    protected $server;
    protected $sessionRepo;
    
    public function __construct(OAuth2PKCEClient $oauth2)
    {
        $this->server = $oauth2;
        $this->sessionRepo = $oauth2->getSessionRepository();
        
    }

    /**
     * We have to check for the route where we place our auth call to the OAuth2 Server.
     * You can use a similar code as below:
     * 
        retun $request->getPathInfo() == '/oauth/check' && $request->isMethod('GET');

     */
    public abstract function supports(Request $request): bool;
    
    /**
     * Abstract function used to retrieve a User once we get the access token.
     * 
     * It has to call the protected function fetchUser($credentials) to receive 
     * an \StdClass object with the information received from the OAuth2 Server.
     * 
     * Example:
     
        $oauthUser = $this->fetchUser($credentials);

        $login = $oauthUser->login;
        $user = $this->em->getRepository(User::class)->findOneBy(['username' => $login]);
            
        if (!$user) {
            $user = new User();
            $user->setUsername($oauthUser->login);
            $user->setEmail($oauthUser->email);
        }
        
        return $user;
     * 
     * @param \StdClass $credentials
     * @param UserProviderInterface $userProvider
     * @return User
     */
    public abstract function getUser($credentials, UserProviderInterface $userProvider);


    public function checkCredentials($credentials, UserInterface $user): bool
    {
        return true;
    }

    public function supportsRememberMe(): bool
    {
        return true;
    }

    /**
     * Function that fetch the credentials once the user authenticates.
     * 
     * @param Request $request
     * @return type
     * @throws AccessDeniedException
     */
    public function getCredentials(Request $request)
    {
        $code = $request->get('code');
        $state = $request->get('state');
        
        $session = $this->sessionRepo->findOneBy(['state'=>$state],['id'=>'DESC']);
        if( $session == null ){
            throw new AccessDeniedException('State received not found!');
        }
        
        $res= $this->fetchAccessToken($session, $code);
        
        // We store the access_token into the session of the user
        $request->getSession()->set('accessToken', $res->access_token );
        
        return $res;
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
    protected function fetchAccessToken(OAuth2Session $session, string $code)
    {
        try {
            return $this->server->getToken($session->getState(), $session->getCodeVerifier(), $code );
        } catch (MissingAuthorizationCodeException $e) {
            throw new NoAuthCodeAuthenticationException();
        } catch (IdentityProviderException $e) {
            throw new IdentityProviderAuthenticationException($e);
        } catch (InvalidStateException $e) {
            throw new InvalidStateAuthenticationException($e);
        }
    }

    protected function fetchUser(\StdClass $credentials){
        
        return $this->server->getOwner($credentials->access_token);
        
    }
    
    /**
     * Returns a response that directs the user to authenticate.
     *
     * This is called when an anonymous request accesses a resource that
     * requires authentication. The job of this method is to return some
     * response that "helps" the user start into the authentication process.
     *
     * Examples:
     *  A) For a form login, you might redirect to the login page
     *      return new RedirectResponse('/login');
     *  B) For an API token authentication system, you return a 401 response
     *      return new Response('Auth header required', 401);
     *
     * @param Request $request The request that resulted in an AuthenticationException
     * @param \Symfony\Component\Security\Core\Exception\AuthenticationException $authException The exception that started the authentication process
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function start(Request $request, \Symfony\Component\Security\Core\Exception\AuthenticationException $authException = null)
    {
        return new RedirectResponse('/login');
    }

    /**
     * Called when authentication executed, but failed (e.g. wrong username password).
     *
     * This should return the Response sent back to the user, like a
     * RedirectResponse to the login page or a 403 response.
     *
     * If you return null, the request will continue, but the user will
     * not be authenticated. This is probably not what you want to do.
     *
     * @param Request $request
     * @param \Symfony\Component\Security\Core\Exception\AuthenticationException $exception
     *
     * @return \Symfony\Component\HttpFoundation\Response|null
     */
    public function onAuthenticationFailure(Request $request, \Symfony\Component\Security\Core\Exception\AuthenticationException $exception)
    {
        // TODO: Implement onAuthenticationFailure() method.
    }

    /**
     * Called when authentication executed and was successful!
     *
     * This should return the Response sent back to the user, like a
     * RedirectResponse to the last page they visited.
     *
     * If you return null, the current request will continue, and the user
     * will be authenticated. This makes sense, for example, with an API.
     *
     * @param Request $request
     * @param \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token
     * @param string $providerKey The provider (i.e. firewall) key
     *
     * @return void
     */
    public function onAuthenticationSuccess(Request $request, \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token, $providerKey)
    {
        // TODO: Implement onAuthenticationSuccess() method.
    }
}
