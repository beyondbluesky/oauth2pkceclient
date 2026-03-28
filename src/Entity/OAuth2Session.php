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
use BeyondBlueSky\OAuth2PKCEClient\Repository\OAuth2SessionRepository;

#[ORM\Entity(repositoryClass: OAuth2SessionRepository::class)]
#[ORM\Table(name: 'security_oauth2_session')]
class OAuth2Session {
    
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private $id;

    #[ORM\Column(type: 'string', length: 180, nullable: true)]
    private $state;
    
    #[ORM\Column(type: 'string', length: 256, nullable: true)]
    private $codeChallenge;
    
    #[ORM\Column(type: 'string', length: 256, nullable: true)]
    private $codeVerifier;
       
    #[ORM\Column(type: 'text', length: 40960, nullable: true)]
    private $accessToken;

    #[ORM\Column(type: 'text', length: 40960, nullable: true)]
    private $refreshToken;

    #[ORM\Column(type: 'string', length: 256, nullable: true)]
    private $userId;

    #[ORM\Column(type: 'string', length: 256, nullable: true)]
    private $audience;

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
     
    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }

    public function setAccessToken(?string $accessToken): self
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    public function setRefreshToken(string $refreshToken): self
    {
        $this->refreshToken = $refreshToken;

        return $this;
    }
    
    public function getUserId(): ?string
    {
        return $this->userId;
    }

    public function setUserId(string $userId): self
    {
        $this->userId = $userId;

        return $this;
    }
    
    public function getAudience(): ?string
    {
        return $this->audience;
    }

    public function setAudience(string $audience): self
    {
        $this->audience = $audience;

        return $this;
    }
}