OAuth2 PKCE Enabled client
===========================

This Symfony bundle allows a Symfony4/5 installation authenticate it's users against an OAuth2 compliant server using the PKCE extension.

The PKCE extension RFC-7636 (https://tools.ietf.org/html/rfc7636) adds additional security to the OAuth2 protocol and it will be mandatory on future versions of OAuth2.

This implementation requires the generation of: 
- An Authenticator
- A Controller to receive the response from the OAuth2 Server
- A table to store the session information (oauth2_session). The table is used to store the session information, including the challenge and verifier strings, used to secure the communication as part
of the PKCE extension. 
- The required config file where we'll store the client_id, oauth2 uris, etc.
- The modification of security.yml to include all the previous configuration

Following you'll find all the steps to configure it. Don't worry...


Installation
-------------

To install it you need to follow the following stemps:

1. Download the latest version of the bundle

```bash
$ composer require beyondbluesky/oauth2-pkce-client 
```
2. Configure the endpoints of your OAuth2 server with a file at config/packages named oauth2_pkce_client:

config/packages/oauth2_pkce_client.yaml:
```yaml
oauth2_pkce_client:
    server_uris:
        auth_uri:   https://oauth2.localnet/oauth2/auth
        token_uri:  https://oauth2.localnet/oauth2/token
        owner_uri:  https://oauth2.localnet/oauth2/owner
    client:
        id: client_id_provided from our oauth2 server
        secret: secret provided from our oauth2 server
        scope: 'authorization_code,user_info,user_auth'
        redirect_uri: https://oauth2client.localnet/oauth2/check
```

3. Create a Controller to receive the tokens, that has to match the redirect_uri path. Following we provide an example code for you to adapt:

src/Controller/OAuth2Controller.php:
```php
namespace App\Controller;

use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

use BeyondBlueSky\OAuth2PKCEClient\Entity\OAuth2Session;
use BeyondBlueSky\OAuth2PKCEClient\DependencyInjection\OAuth2PKCEClientExtension as OAuth2PKCEClient;

/**
 * Default App controller.
 *
 * @Route("/oauth2")
 */
class OAuth2Controller extends AbstractController
{
    
    /**
     * @Route("/login", name="oauth_login", methods={"GET"})
     */ 
    public function oauthLogin(Request $request, OAuth2PKCEClient $oauth2)
    {
        
        $session = new OAuth2Session();
        $response= $oauth2->getAuthRedirect($session);

        $this->getDoctrine()->getManager()->persist($session);
        $this->getDoctrine()->getManager()->flush();
        
        return $response;
    }
    
    /**
     * @Route("/check", name="oauth_check", methods={"GET"})
     */ 
    public function oauthRedirect(Request $request)
    {
        $user= $this->getUser();
        if ($user == null ) {
            return new Response(json_encode( ['status' => false, 'message' => "User not found!"] ) );
        } else {
            return $this->redirectToRoute('homepage');
        }
    }
    
}
```

4. Create a user class. The minimum information should be the username. All other 
fields are optional and filled in the point 5 of this guide. In our case we'll create a Security\User inside the Entity folder.

If you are new to this, I highly recommend to use the command 

```bash
$ bin/console make:entity
```

And follow the questions asked, adding the username field and all the fields you need for your project. 
That will generate an ORM configured entity with all the information needed.

5. Now we need a new Authenticator. Use to following code as a template:

src/Security/OAuth2Authenticator.php:
```php

namespace App\Security;

use App\Entity\Security\User;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserProviderInterface;

use Doctrine\ORM\EntityManagerInterface;

use BeyondBlueSky\OAuth2PKCEClient\DependencyInjection\OAuth2PKCEClientExtension as OAuth2PKCEClient;
use BeyondBlueSky\OAuth2PKCEClient\Security\OAuth2PKCEAuthenticator;

/**
 */
class OAuth2Authenticator extends OAuth2PKCEAuthenticator
{
    private $em;
    
    public function __construct(EntityManagerInterface $em, OAuth2PKCEClient $oauth2 ) {
        $this->em = $em;
        
        parent::__construct($oauth2);
        
    }
    
    public function supports(Request $request): bool{
        return $request->getPathInfo() == '/oauth2/check' && $request->isMethod('GET');
    }
    
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        // With this function we fetch the user's data from the credentials
        $oauthUser = $this->fetchUser($credentials);
    
        $login = $oauthUser->login;
        $user = $this->em->getRepository(User::class)->findOneBy(['username' => $login]);
            
        if (! $user ) {
            // Now we have to adapt to our local User 
            $user = new User();
            $user->setUsername($oauthUser->login);
            $user->setEmail($oauthUser->email);
            $user->setName($oauthUser->name);
            $user->setSurname1($oauthUser->surname1);
            $user->setSurname2($oauthUser->surname2);
            $user->setPassword('-');
            $user->setRoles(['ROLE_USER']);
            //$user->setFullname($oauthUser['name']. " ".$oauthUser['surname1']. " ".$oauthUser['surname2']);
            $user->setCreatedAt(new \DateTime(date('Y-m-d H:i:s')));
            $this->em->persist($user);
            $this->em->flush();
        }
        return $user;   
    }   
}
```

6. Update your database schema: schema:update or doctrine:migrations, your choice.

```sh
$ bin/console doctrine:schema:update --force
```

7. Configure the security.yaml to point to our new authenticator

On the providers section replace the in-memory line for:

config/packages/security.yaml:
```yaml
        oauth_user_provider:
            entity:
                class: App\Entity\Security\User
                property: username
```
And on firewalls > main refer to your new user provider and add our authenticator created at step 5:
```yaml
    firewalls:
        main:
            provider: oauth_user_provider
            guard:
                authenticators:
                    - App\Security\OAuth2Authenticator
```

8. Enjoy your new OAuth2 authentication! For that go to your Symfony root on a browser and add a oauth2/login to the URL (if you didn't change the
paths on the OAuth2Controller). Now you should see the login page of your OAuth2 server.

Have fun!