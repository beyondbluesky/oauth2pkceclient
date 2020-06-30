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

use Symfony\Component\HttpFoundation\Session\SessionInterface;

use BeyondBlueSky\LibJWT\Entity\JWToken;
use BeyondBlueSky\LibJWT\DependencyInjection\JWTServiceExtension as JWTService;

use BeyondBlueSky\OAuth2PKCEClient\Entity\Exception\TokenNotFoundException;
use BeyondBlueSky\OAuth2PKCEClient\Entity\Exception\EmptyResponseException;

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
    private $ownTenantUri;
    
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
             
        if( isset($config['server_uris']['owntenant_uri']) ){
            $this->ownTenantUri = $config['server_uris']['owntenant_uri'];
        }else {
            $this->ownTenantUri = null;
        }
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

    /**
     * This function builds the call to fetch the auth endpoint
     * 
     * @param OAuth2Session $session
     * @param array $extraParameters
     * @return RedirectResponse
     */
    public function getAuthRedirect(OAuth2Session $session, array $extraParameters= [] ): RedirectResponse {

        $verifier = $this->generateCodeVerifier();
        $challenge = $this->getCodeChallenge($verifier);
        $state = $this->getRandomString(16);

        $session->setCodeVerifier($verifier);
        $session->setCodeChallenge($challenge);
        $session->setState($state);
        
        // Used for advanced security and multi-client authentication on same
        // oauth server
        if( isset($extraParameters['audience']) ){
            $session->setAudience($extraParameters['audience']);
        }
        
        $basicConfig= [
            'client_id'=> $this->clientId,
            'redirect_uri'=> $this->redirectUri,
            'scope'=> $this->scope,
            'code_challenge'=> $challenge,
            'code_challenge_method'=> 'S256',
            'state' => $state,
            ];     
        
        // We exclude the standard parameters already defined at basic Config
        $cleanExtraConfig = array_diff( $extraParameters, $basicConfig);
        // We merge the remaining params to the final config parameters.
        $config = array_merge( $basicConfig, $cleanExtraConfig);
        
        $response= new RedirectResponse($this->authServerUri.'?'.$this->encodeParams($config) );
        
        return $response;
    }
    
    /**
     * This function fetches the auth endpoint using a special id_token_hint 
     * flow that allows the retrieval of a token based on another current 
     * access_token. 
     * 
     * Used for multi-client access based on same oauth server.
     * 
     * @param OAuth2Session $session
     * @param string $userId
     * @param array $extraParameters
     * @return type
     * @throws Exception
     */
    public function getAuthRedirectRenew(OAuth2Session $session, string $userId, array $extraParameters= [] ): RedirectResponse {

        $oldSession = $this->sessionRepo->findOneBy(['userId'=>$userId]);
        
        if( ! $oldSession ){
            throw new TokenNotFoundException('User not found');
        }
        $token = $oldSession->getAccessToken();
        
        $extraConfig= [
            'id_token_hint'=> $token,
            'prompt'=>'none'
            ];     
        
        $extraConfig = array_merge($extraConfig, $extraParameters);
        
        return $this->getAuthRedirect($session, $extraConfig);
    }
    
    /**
     * Renews a token using the id_token_hint flow. This function has to be used internally, since makes all the
     * workflow without user intervention.
     * 
     * @param RedirectResponse $username
     * @param array $parameters
     */
    public function fetchAuthRedirectRenew(string $username, string $audience){
        
        $session = new OAuth2Session();
        $authUrl = $this->getAuthRedirectRenew($session, $username, ['audience'=>$audience] );
        
        $token= $this->fetchAuthRedirectRenew0( $authUrl, $session );
        
        if( isset($token->access_token) ){
            $session->setUserId($username);
            $session->setAccessToken($token->access_token);
            $session->setRefreshToken($token->refresh_token);
            $this->sessionRepo->persist($session);
        }else {
            throw new TokenNotFoundException("id_token_hint answer without token!");
        }     
    }
    
    private function fetchAuthRedirectRenew0(RedirectResponse $authUrl, $session ){
        $resp= new \stdClass();
        
        $url= $authUrl->getTargetUrl();
        $header= $this->cURLHeader($url);
        
        $redirUrl= '';
        if( isset($header['redirect_url'])){
            $redirUrl = $header['redirect_url'];
            $params = explode('?', $redirUrl);
            $params = $this->parseParams($params);
            if( isset($params['code']) ){
                //var_dump($code);die;
                $resp = $this->getToken($session->getState(), $session->getCodeVerifier(), $params['code'] );
            }else {
                throw new TokenNotFoundException('No code received '. json_encode($params));
            }
        }else {
            throw new TokenNotfoundException('No redirect Uri received.');
        }
        return $resp;
    }
    
    private function parseParams(array $src): array {
        // We receive an array with first item the url and second the params
        if( sizeof($src) > 1 ){
            // We parse the parameters (delimiter &)
            return $this->parseParams0( explode('&', $src[1]) ); 
        }
        
        return [];
    }
    
    private function parseParams0(array $src): array {
        $out= [];
        foreach($src as $v){
            $vArray = explode('=', $v);
            if(sizeof($vArray) > 1){
                $out[$vArray[0]]= $vArray[1];
            }else{
                $out[$vArray[0]]= '';
            }
        }
        
        return $out;
    }
    
    /**
     * Fetches a token
     * 
     * @param string $state
     * @param string $verifier
     * @param string $code
     * @return type
     * @throws EmptyResponseException
     */
    public function getToken(string $state, string $verifier, string $code){
        
        $header= ['Authorization'=> 'Basic '. base64_encode($this->clientId.":".$this->clientSecret)];
        $header= ['Authorization2'=> 'Basic '.base64_encode($this->clientId.":".$this->clientSecret)];
        
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
            throw new EmptyResponseException($response);
        }  
        return $jsonResponse;
        
    }
    
    public function refreshToken(SessionInterface $session){
        $refreshToken = $session->get('refreshToken');
    
        $header= ['Authorization'=> 'Basic '.base64_encode($this->clientId.":".$this->clientSecret)];
        $header= ['Authorizatio2'=> 'Basic '.base64_encode($this->clientId.":".$this->clientSecret)];
        
        $paramArray = [
            'grant_type'    => 'refresh_token',
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri'  => $this->redirectUri,
            'refresh_token' => $refreshToken,   
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
            throw new EmptyResponseException($response);
        }  
        
        if( ! isset($jsonResponse->access_token) ){
            throw new \Exception('Wrong response from server: '.$response);
        }
        $session->set('accessToken', $jsonResponse->access_token);
        $session->set('refreshToken', $jsonResponse->refresh_token);
        
        return $session;
        
    }
    
    public function getOwner(string $accessToken):?\stdClass{
        
        $header= ['Authorization'=> 'Bearer '.$accessToken ];
        $header= ['Authorization2'=> 'Bearer '.$accessToken ];
        
        $paramArray = [
            ];
        
        $response= $this->get($this->ownerServerUri, $header, $this->encodeParams($paramArray));
        
        return json_decode($response);
        
    }
    
    public function getOwnTenant(string $accessToken):?\stdClass{
        $response = '{}';
        
        if( $this->ownTenantUri != null ){
            $header= ['Authorization'=> 'Bearer '.$accessToken ];
            $header= ['Authorization2'=> 'Bearer '.$accessToken ];

            $paramArray = [
                ];

            $response= $this->get($this->ownTenantUri, $header, $this->encodeParams($paramArray));
        }
        
        return json_decode($response);
        
    }
    
    /**
     * Using tokens already obtained from an oauth server, it fetches a URL using
     * a token
     * 
     * @param string $audience
     * @param string $userId
     * @param string $url
     * @param array $params
     * @return type
     */
    public function getSecureUrl(string $audience, string $userId, string $url, array $params=[]){
        $response = null;
        
        $session = $this->sessionRepo->findByAudience($userId, $audience);
        if( ! $session ){
            throw new TokenNotFoundException('Token not found!');
        }

        $header= ['Authorization'=> 'Bearer '.$session->getAccessToken() ];
        $header= ['Authorization2'=> 'Bearer '.$session->getAccessToken() ];

        if( strtoupper($method) == 'GET'){
            
            $response= $this->get($url, $header, $this->encodeParams($params));
            
        }else if( strtoupper($method) == 'LIST'){
            
            $response= $this->get($url."?_method=LIST", $header, $this->encodeParams($params));
            
        }else if( strtoupper($method) == 'DELETE'){
            
            $response= $this->get($url."?_method=DELETE", $header, $this->encodeParams($params));
            
        }else if( strtoupper($method) == 'POST'){

            $response= $this->post($url, $header, $this->encodeParams($params));
            
        }else if( strtoupper($method) == 'PUT'){
            
            $params = array_merge( $params, ['_method'=>'PUT']);
            $response= $this->post($url, $header, $this->encodeParams($params));
            
        }else {
            
            throw new \Exception('Wrong method requested. Allowed: GET, PUT, LIST, DELETE, POST');
        }
        return $response;                
        
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
            //CURLOPT_FOLLOWLOCATION  => true,
            //CURLOPT_CUSTOMREQUEST   => "GET",
                   // CURLOPT_HEADER => TRUE,
            CURLOPT_HTTPHEADER      => $this->packKeys($headers),
                ];

        return $this->cURL($curlOpts, $tlsCert, $keyTlsCert);
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

        return $this->cURL($curlOpts, $tlsCert, $keyTlsCert);
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
    
    private function cURLHeader(string $url){

        $curlOpts=  
                [
            CURLOPT_URL             => $url, 
                    CURLOPT_HEADER  => true,
            CURLOPT_HTTPGET         => true,
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_MAXREDIRS       => 10,
            CURLOPT_TIMEOUT         => 30,
            CURLOPT_HTTP_VERSION    => CURL_HTTP_VERSION_1_1,
            //CURLOPT_FOLLOWLOCATION  => true,
            //CURLOPT_CUSTOMREQUEST   => "GET",
                   // CURLOPT_HEADER => TRUE,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_SSL_VERIFYPEER => 0 ,                    
            CURLOPT_HTTPHEADER      => $this->packKeys([]),
                ];

        $curl = curl_init();
        curl_setopt_array($curl, $curlOpts);
        curl_exec($curl); //hit the $url
        $curl_info = curl_getinfo($curl);
        
        return $curl_info;        
    }

    private function cURL(array $curlOpts, string $tlsCert= null, string $keyTlsCert= null){
     
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
          throw new \Exception("cURL Error #:" . $err);
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
