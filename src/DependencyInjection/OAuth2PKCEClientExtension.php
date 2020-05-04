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

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;

use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\Config\FileLocator;

use Symfony\Component\HttpFoundation\RedirectResponse;

use BeyondBlueSky\OAuth2PKCEClient\Entity\OAuth2Session;
use BeyondBlueSky\OAuth2PKCEClient\Repository\OAuth2SessionRepository;

/**
 * This service gives an interface to an OAuth2 PKCE compliant server
 */
class OAuth2PKCEClientExtension extends Extension {
    
    public static $CLIENT_TYPE_BASIC= 0;
    public static $CLIENT_TYPE_PKCE= 1;
    
    private $clientId;
    private $clientSecret;
    
    private $authServerUri;
    private $tokenServerUri;
    private $ownerServerUri;
    
    private $redirectUri;
    private $scope;
    
    private $clientType;
    
    private $sessionRepo;
    
    public function __construct(array $server_uris= [], array $client=[], OAuth2SessionRepository $sessionRepo= null ) {
        if( sizeof($client) > 0 && sizeof($server_uris) > 0 ){
            $this->loadConfig(['server_uris'=> $server_uris, 'client'=> $client]);
        }
        $this->sessionRepo = $sessionRepo;
        
    }
    
    public function load(array $configs, ContainerBuilder $container)
    {
        $loader = new YamlFileLoader(
            $container,
            new FileLocator(__DIR__.'/../Resources/config')
            );
        $loader->load('services.yml');
        
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $definition = $container->getDefinition(OAuth2PKCEClientExtension::class);
        $definition->replaceArgument(0, $config['server_uris'] );
        $definition->replaceArgument(1, $config['client']);
        
    }
    
    
    public function getSessionRepository():? OAuth2SessionRepository {
        return $this->sessionRepo;
    }
    
    private function loadConfig(array $config){
        $this->clientId       = $config['client']['id'];
        $this->clientSecret   = $config['client']['secret'];
        $this->redirectUri    = $config['client']['redirect_uri'];
        $this->scope          = $config['client']['scope'];
        
        $this->authServerUri  = $config['server_uris']['auth_uri'];
        $this->tokenServerUri = $config['server_uris']['token_uri'];
        $this->ownerServerUri = $config['server_uris']['owner_uri'];
             
    }
    /*
    public function getContainerExtension()
    {
        return new OAuth2PKCEClientExtension();
    }
    */
    public function getAlias(){
        return "oauth2_pkce_client";
    }
    
    public function setClientType(int $clientType){
        $this->clientType = $clientType;
    }

    public function getAuthRedirect(OAuth2Session $session) {

        $verifier = $this->generateCodeVerifier();
        $challenge = $this->getCodeChallenge($verifier);
        $state = $this->getRandomString(16);

        $session->setCodeVerifier($verifier);
        $session->setCodeChallenge($challenge);
        $session->setState($state);
        
        $response= new RedirectResponse($this->authServerUri.'?'.$this->encodeParams([
            'client_id'=> $this->clientId,
            'redirect_uri'=> $this->redirectUri,
            'scope'=> $this->scope,
            'code_challenge'=> $challenge,
            'code_challenge_method'=> 'S256',
            'state' => $state,
            ]));     
        
        return $response;
    }
    
    public function getToken(string $state, string $verifier, string $code){
        
        $header= ['Authorization'=> 'Basic '.base64_encode($this->clientId.":".$this->clientSecret)];
        
        $paramArray = [
            'grant_type'    => 'authorization_code',
            'state'         => $state,
            'code'          => $code,
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri'  => $this->redirectUri,
            'code_verifier' => $verifier,   
        ];
        
        $response= $this->post($this->tokenServerUri, $header, $this->encodeParams($paramArray));
        /* Response: 
         * { 
         *  ["access_token"]=> string(256) "9M37DDYNo8ehL8LBy1xfwSKB1mUzHGTofi1sA2nJRp8YqwYdhNHHMk8N0Mx6VXrFIDiT12MPiMWxEcdNsy8FPxDgTnGx2w7M7Ch78BTTKNxfm5wT0sqpD6cM2oQXxZLQauJyfRoifNasEeMWTWley3JfyTukW5XFATqe0sB9aaCmFHrFXOOTJjUWBIS9gRRmeymtbCTB9OlIR8IaKs1F3YnMsJdNub4vQs1CDQs8Kq2E3xZl1Edt7Lz5yOxGJKK7" 
         *  ["refresh_token"]=> string(256) "cD00hcBZaUDIODOwUKXcEpvdzGJTAvX2WlUT9xOCjv3BsXXFzo20HqcMV2tF6u2d5gDRhYPAYapHNFdem9Ia1pvGfqvbxhBvULhHAZqqLL0A5ffoEN70dgGbR7WyQCjElvJ1O8uWCEmGDIoTZznrYZITkm8i12QBl3C6Fq5sNojt5ojW0iYVS00QLkJseOK4ZvRPb0dQDdZxLP7iI26NhSInaDTNdeSTkNriZqYh520Kf3NmXik55yvD08oWO3za" 
         *  ["expires_in"]=> int(300) 
         *  ["resource_owner_id"]=> string(13) "test@test.com" 
         * } 
         */
        $jsonResponse = json_decode($response);
        if( $jsonResponse == null ){
            throw new Exception($response);
        }  
        return $jsonResponse;
        
    }
    
    public function getOwner(string $accessToken):?\stdClass{
        
        $header= ['Authorization'=> 'Bearer '.$accessToken ];
        
        $paramArray = [
            ];
        
        $response= $this->get($this->ownerServerUri, $header, $this->encodeParams($paramArray));
        
        return json_decode($response);
        
    }
    
    private function get(string $url, array $headers, string $tlsCert= null, string $keyTlsCert= null){
        
        $curlOpts=  
                [
            CURLOPT_URL             => $url, 
            CURLOPT_HTTPGET         => true,
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_MAXREDIRS       => 10,
            CURLOPT_TIMEOUT         => 30,
            CURLOPT_HTTP_VERSION    => CURL_HTTP_VERSION_1_1,
            //CURLOPT_CUSTOMREQUEST   => "GET",
            CURLOPT_HTTPHEADER      => $this->packKeys($headers),
                ];

        return $this->cURL($url, $curlOpts, $tlsCert, $keyTlsCert);
    }
        
    private function post(string $url, array $headers, string $body, string $tlsCert= null, string $keyTlsCert= null){
        
        $curlOpts=  
                [
            CURLOPT_URL             => $url, 
            CURLOPT_POST            => true,
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_MAXREDIRS       => 10,
            CURLOPT_TIMEOUT         => 30,
            CURLOPT_HTTP_VERSION    => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST   => "POST",
            CURLOPT_HTTPHEADER      => $this->packKeys($headers),
            CURLOPT_POSTFIELDS      => $body,
                ];

        return $this->cURL($url, $curlOpts, $tlsCert, $keyTlsCert);
    }
    
    /**
     * CORS response for JS calls
     * 
     * @param string $method
     * @return Response
     */
    private function responseAllowMethod(string $method): Response{
        $resp= new Response();
        
        $resp->headers->set('Access-Control-Allow-Origin','*');
        $resp->headers->set('Access-Control-Allow-Headers', $method);
        
        return $resp;
    }
    
    /**
     * Generates a code verifier. RFC-7636
     * 
     * @return \self
     */
    public function generateCodeVerifier(): string {
        
        return $this->urlSafeB64Encode(random_bytes(64));
        
    }
    
    public function getCodeChallenge(string $codeVerifier ){
        
        $strHash= hash("SHA256", $codeVerifier, true);
        $str64= $this->urlSafeB64Encode($strHash);

        return $str64;        
    }
    
    /**
     * 
     * Appendix A: IETF 7636
     * 
        static string base64urlencode(byte [] arg)
        {
          string s = Convert.ToBase64String(arg); // Regular base64 encoder
          s = s.Split('=')[0]; // Remove any trailing '='s
          s = s.Replace('+', '-'); // 62nd char of encoding
          s = s.Replace('/', '_'); // 63rd char of encoding
          return s;
        }
     * 
     * @param type $data
     * @return string
     */
    /**
    * base64url encoding.
    * @param  String $input    Data to be encoded. 
    * @param  Int    $nopad    Whether "=" pad the output or not. 
    * @param  Int    $wrap     Whether to wrap the result. 
    * @return base64url encoded $input. 
    */
   public function urlSafeB64Encode($input,$nopad=1,$wrap=0)
   {
       $data  = base64_encode($input);

       if($nopad) {
           $data = str_replace("=","",$data);
       }
       $data = strtr($data, '+/=', '-_,');
       if ($wrap) {
           $datalb = ""; 
           while (strlen($data) > 64) { 
               $datalb .= substr($data, 0, 64) . "\n"; 
               $data = substr($data,64); 
           } 
           $datalb .= $data; 
           return $datalb; 
       } else {
           return $data;
       }
   }
   
    /*
    public function urlSafeB64Encode($data): string
    {
        $b64 = base64_encode($data);
        $b64 = explode('=', $b64)[0];
        $b64 = str_replace('+','-', $b64);
        $b64 = str_replace('/','_', $b64);
        
        return $b64;
    }
    */
    public function urlSafeB64Decode($b64): string
    {
        $b64 = str_replace('-','+', $b64);
        $b64 = str_replace('_','/', $b64);
        
        return base64_decode($b64);
    }

    /**
     * Returns a random string with the size referred
     * @param type $size
     * @return string
     */
    private function getRandomString($size) { 
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'; 
        $randomString = ''; 

        for ($i = 0; $i < $size; $i++) { 
            $index = rand(0, strlen($characters) - 1); 
            $randomString .= $characters[$index]; 
        } 

        return $randomString; 
    }
    

    private function cURL(string $url, array $curlOpts, string $tlsCert= null, string $keyTlsCert= null){
     
        $curl = curl_init();
        curl_setopt_array($curl, $curlOpts);
        
        //if( $this->env == 'dev'){
            curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);                        
        //}
        
        if( $tlsCert != null && $keyTlsCert != null ){
            $tlsCertFile= tempnam("/tmp",'tls-');
            file_put_contents($tlsCertFile, $tlsCert);
            $tlsKeyFile= tempnam("/tmp",'tls-');
            file_put_contents($tlsKeyFile, $keyTlsCert);
            
            curl_setopt($curl, CURLOPT_SSLCERT, $tlsCertFile);
            curl_setopt($curl, CURLOPT_SSLKEY, $tlsKeyFile);
        }
        
        $response = curl_exec($curl);
        
        $err   = curl_error($curl); 
        $errNo = curl_errno($curl);
        curl_close($curl);

        if( $tlsCert != null && $keyTlsCert != null ){
            unlink($tlsCertFile);
            unlink($tlsKeyFile);
        }
        if ($err) {
          return "cURL Error #:" . $err;
        } else {
          return $response;
        }
    }

    /**
     * Encodes an array as url_safe parameter for a GET request
     * 
     * @param array $params
     * @return string
     */
    private function encodeParams(array $params): string{
        $out= "";
        foreach($params as $k=>$v){
            $out .= $k."=".urlencode($v)."&";
        }

        return substr($out, 0, -1); 
    }   
    
    private function packKeys(array $in){
        $out= [];
        foreach($in as $key=>$val){
            $out[]= $key.": ".$val;
        }
        
        return $out;
    }
    
    
}
