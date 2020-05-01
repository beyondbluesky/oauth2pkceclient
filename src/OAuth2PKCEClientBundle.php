<?php

/* 
 * The Creative Commons BY-NC-SA 4.0 License
 * Attribution-NonCommercial-ShareAlike 4.0 International
 * Josep Llauradó Selvas
 * pep@beyondbluesky.com
 * 
 * 
*/

namespace BeyondBlueSky\OAuth2PKCEClient;

use BeyondBlueSky\OAuth2PKCEClientBundle\DependencyInjection\OAuth2PKCEClientExtension;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class OAuth2PKCEClientBundle extends Bundle
{
    /**
     * Overridden to allow for the custom extension alias.
     *
     * @return KnpUOAuth2ClientExtension
     *
    public function getContainerExtension()
    {
        if (null === $this->extension) {
            return new OAuth2PKCEExtension();
        }

        return $this->extension;
    }*/
}
