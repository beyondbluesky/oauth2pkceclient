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

namespace BeyondBlueSky\OAuth2PKCEClient\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('oauth2_pkce_client');
        $rootNode = method_exists($treeBuilder, 'getRootNode')
            ? $treeBuilder->getRootNode()
            : $treeBuilder->root('oauth2_pkce_client');

        $rootNode
            ->children()
                ->arrayNode('server_uris')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('auth_uri')->end()
                        ->scalarNode('token_uri')->end()
                        ->scalarNode('owner_uri')->end()
                        ->scalarNode('owntenant_uri')->end()
                        //->booleanNode('tlsEnabled')->info('Use if you want a TLS Client cert connection')->end()
                    ->end()
                ->end()
                ->arrayNode('client')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('id')->end()
                        ->scalarNode('secret')->end()
                        ->scalarNode('redirect_uri')->end()
                        ->scalarNode('scope')->end()
                    ->end()
                ->end()
            ->end()
            ->validate()
                ->ifTrue(function ($v) {
                    return ! isset($v['server_uris'], $v['client']);
                })
                ->thenInvalid('Missing parameters.')
            ->end()
        ;

        return $treeBuilder;
    }
}
