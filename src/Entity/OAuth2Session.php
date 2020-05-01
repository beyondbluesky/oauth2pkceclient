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

namespace BeyondBlueSky\OAuth2PKCEClient\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Entity(repositoryClass="BeyondBlueSky\Repository\OAuth2SessionRepository")
 * @ORM\Table(name="security_oauth2_session") 
 * 
 */
class OAuth2Session {
    
    /**
     * @ORM\Id()
     * @ORM\GeneratedValue()
     * @ORM\Column(type="integer")
     */
    private $id;

    /**
     *
     * @ORM\Column(type="string", length=180, nullable=true)
     * @var string
     */
    private $state;
    
    /**
     *
     * @ORM\Column(type="string", length=256, nullable=true)
     * @var string
     */
    private $codeChallenge;
    
    /**
     *
     * @ORM\Column(type="string", length=256, nullable=true)
     * @var string
     */
    private $codeVerifier;
    
    public function setState($state){
        $this->state = $state;
        
        return $this;
    }

    public function getState(){
        return $this->state;
    }
    
    public function setCodeChallenge($codeChallenge){
        $this->codeChallenge = $codeChallenge;
        
        return $this;
    }

    public function getCodeChallenge(){
        return $this->codeChallenge;
    }
    
    public function setCodeVerifier($codeVerifier){
        $this->codeVerifier = $codeVerifier;
        
        return $this;
    }

    public function getCodeVerifier(){
        return $this->codeVerifier;
    }
        
}