<?php

$endpoint = new endpoint();
$endpoint->setSecret('secret');
$endpoint->setApikey('apikey');
$endpoint->setAlloweduri(array(
    'yourdomain.de',
));