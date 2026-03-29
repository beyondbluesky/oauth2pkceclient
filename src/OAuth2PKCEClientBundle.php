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

use BeyondBlueSky\OAuth2PKCEClient\DependencyInjection\OAuth2PKCEClientExtension;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class OAuth2PKCEClientBundle extends Bundle
{
    /**
     * Overridden to allow for the custom extension alias.
     */
    public function getContainerExtension(): ?ExtensionInterface
    {
        if (null === $this->extension) {
            return new OAuth2PKCEClientExtension();
        }

        return $this->extension;
    }
}
