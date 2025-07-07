<?php

/**
 *
 */
class endpoint{

    /**
     * @var array
     */
    private array $_alloweduri;
    /**
     * @var array
     */
    private array $_endpoints;
    /**
     * @var string
     */
    private string $_apitoken;
    /**
     * @var string
     */
    private string $_apikey;
    /**
     * @var string
     */
    private string $_secret;

    /**
     * @return array
     */
    public function getAlloweduri(): array
    {
        return $this->_alloweduri;
    }

    /**
     * @param array $alloweduri
     * @return void
     */
    public function setAlloweduri(array $alloweduri): void
    {
        $this->_alloweduri = $alloweduri;
    }


    /**
     * @return string
     */
    public function getApitoken(): string
    {
        return $this->_apitoken;
    }

    /**
     * @param string $apitoken
     * @return void
     */
    public function setApitoken(string $apitoken): void
    {
        $this->_apitoken = $apitoken;
    }

    /**
     * @return array
     */
    public function getEndpoints(): array
    {
        return $this->_endpoints;
    }

    /**
     * @param array $endpoints
     * @return void
     */
    public function setEndpoints(array $endpoints): void
    {
        $this->_endpoints = $endpoints;
    }

    /**
     * @return string
     */
    public function getApikey(): string
    {
        return $this->_apikey;
    }

    /**
     * @param string $apikey
     * @return void
     */
    public function setApikey(string $apikey): void
    {
        $this->_apikey = $apikey;
    }

    /**
     * @return string
     */
    public function getSecret(): string
    {
        return $this->_secret;
    }

    /**
     * @param string $secret
     * @return void
     */
    public function setSecret(string $secret): void
    {
        $this->_secret = $secret;
    }


}