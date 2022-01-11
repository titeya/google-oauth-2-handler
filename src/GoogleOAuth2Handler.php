<?php

namespace Titeya\GoogleOAuth2Handler;

use GuzzleHttp\Psr7\Request;

class GoogleOAuth2Handler
{
    private $clientId;
    private $clientSecret;
    private $scopes;
    private $clientCredentials;
    private $client;
    
    public $authUrl;

    public function __construct($clientId, $clientSecret, $scopes, $clientCredentials = '')
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->scopes = $scopes;
        $this->clientCredentials = $clientCredentials;

        $this->setupClient();
    }

    private function setupClient()
    {
        $this->client = new \Google_Client();

        $this->client->setClientId($this->clientId);
        $this->client->setClientSecret($this->clientSecret);
        $this->client->setRedirectUri('urn:ietf:wg:oauth:2.0:oob');
        $this->client->setAccessType('offline');
        $this->client->setApprovalPrompt('force');

        
        foreach($this->scopes as $scope)  {
            $this->client->addScope($scope);
        }
        
        if ($this->clientCredentials) {
            $this->client->setAccessToken($this->clientCredentials);
            if ($this->client->isAccessTokenExpired()) {
                $this->client->refreshToken($this->client->getRefreshToken());
            }
        } else {
            $this->authUrl = $this->client->createAuthUrl();
        }
    }

    public function getRefreshToken($authCode)
    {
        $this->client->authenticate($authCode);
        $accessToken = $this->client->getAccessToken();
        return $accessToken;
    }

    public function getToken()
    {
        return $this->client->getAccessToken();
    }

    public function performRequest($method, $url, $body = null)
    {
        $httpClient = $this->client->authorize();
        $request = new Request($method, $url, [], $body);
        $response = $httpClient->send($request);
        return $response;
    }

}
