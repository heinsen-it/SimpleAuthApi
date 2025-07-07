<?php

class routing {

    private string $_endpoint;

    public function __construct($requri){
      $this->_endpoint = trim(parse_url($requri, PHP_URL_PATH), '/');
    }


    public function validate(array $endpoints){

        if(!is_array($endpoints)){

        }

    }


}
