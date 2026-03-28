OAuth2 PKCE Enabled Client
==========================

This Symfony bundle allows a Symfony 8 application to authenticate users against an OAuth2-compliant server using PKCE (RFC 7636).

Compatibility
-------------

- PHP: 8.4+
- Symfony: 8.x

Requirements Overview
---------------------

To integrate the bundle, you need:

- A custom authenticator based on Symfony's modern authenticator system
- A controller endpoint that matches your OAuth2 redirect URI
- A table to store PKCE state, verifier, challenge, and issued tokens
- A bundle config file with client and server OAuth2 settings
- Security firewall configuration that uses custom_authenticators

Installation
------------

1. Install the package:

```bash
composer require beyondbluesky/oauth2-pkce-client
```

2. Create the bundle config file:

config/packages/oauth2_pkce_client.yaml

```yaml
oauth2_pkce_client:
    server_uris:
        auth_uri: https://oauth2.localnet/oauth2/auth
        token_uri: https://oauth2.localnet/oauth2/token
        owner_uri: https://oauth2.localnet/oauth2/owner
    client:
        id: '%env(resolve:OAUTH2_CLIENT)%'
        secret: '%env(resolve:OAUTH2_SECRET)%'
        scope: '%env(resolve:OAUTH2_SCOPE)%'
        redirect_uri: '%env(resolve:OAUTH2_REDIRECT)%'
        server_cert: '%env(resolve:OAUTH2_SERVER_CERT)%'
        cert: '%env(resolve:OAUTH2_CLIENT_CERT)%'
        cert_key: '%env(resolve:OAUTH2_CLIENT_CERT_KEY)%'
```

3. Create the OAuth2 controller with route attributes:

src/Controller/OAuth2Controller.php

```php
<?php

namespace App\Controller;

use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use BeyondBlueSky\OAuth2PKCEClient\DependencyInjection\OAuth2PKCEClientExtension as OAuth2PKCEClient;
use BeyondBlueSky\OAuth2PKCEClient\Entity\OAuth2Session;

#[Route('/oauth2')]
class OAuth2Controller extends AbstractController
{
    #[Route('/login', name: 'oauth_login', methods: ['GET'])]
    public function oauthLogin(OAuth2PKCEClient $oauth2, EntityManagerInterface $entityManager): Response
    {
        $session = new OAuth2Session();
        $response = $oauth2->getAuthRedirect($session);

        $entityManager->persist($session);
        $entityManager->flush();

        return $response;
    }

    #[Route('/check', name: 'oauth_check', methods: ['GET'])]
    public function oauthRedirect(Request $request): Response
    {
        return $this->redirectToRoute('homepage');
    }
}
```

4. Create a User entity implementing modern security interfaces:

```php
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    public function getUserIdentifier(): string
    {
        return $this->username;
    }

    public function getRoles(): array
    {
        return ['ROLE_USER'];
    }

    public function getPassword(): string
    {
        return '-';
    }

    public function eraseCredentials(): void
    {
    }
}
```

5. Implement your authenticator by extending OAuth2PKCEAuthenticator:

src/Security/OAuth2Authenticator.php

```php
<?php

namespace App\Security;

use App\Entity\Security\User;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserInterface;
use BeyondBlueSky\OAuth2PKCEClient\Security\OAuth2PKCEAuthenticator;

class OAuth2Authenticator extends OAuth2PKCEAuthenticator
{
    public function supports(Request $request): bool
    {
        return $request->getPathInfo() === '/oauth2/check' && $request->isMethod('GET');
    }

    public function getUser($credentials): ?UserInterface
    {
        $oauthUser = $this->fetchUser($credentials);

        $user = $this->em->getRepository(User::class)->findOneBy([
            'username' => $oauthUser->login,
        ]);

        if (! $user) {
            $user = new User();
            $user->setUsername($oauthUser->login);
            $user->setEmail($oauthUser->email ?? null);
            $user->setPassword('-');
            $user->setRoles(['ROLE_USER']);
            $this->em->persist($user);
            $this->em->flush();
        }

        return $user;
    }
}
```

6. Configure security.yaml to use custom_authenticators:

config/packages/security.yaml

```yaml
security:
    password_hashers:
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface: 'auto'

    providers:
        oauth_user_provider:
            entity:
                class: App\Entity\Security\User
                property: username

    firewalls:
        main:
            lazy: true
            provider: oauth_user_provider
            custom_authenticators:
                - App\Security\OAuth2Authenticator
```

7. Create or run your Doctrine migration:

```bash
php bin/console doctrine:migrations:diff
php bin/console doctrine:migrations:migrate
```

8. Start authentication by opening:

```text
/oauth2/login
```

If your redirect URI and OAuth2 server config are correct, the PKCE login flow should start.