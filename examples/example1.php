<?php

require '../config.php';
require '../src/TalkspiritClient.class.php';

try {
    $client = TalkspiritClient::getInstance();
    $client->setConfig($config);
    $token = $client->connectUser('noreply@talkspirit.fr', 'password'); // by default noreply@talkspirit.fr is the anonymous user
    if($token) {
        // we can keep the token for the next requests in session for example. The token does not expire
        $response = $client->setPath('/users/search')
                            ->setQuery(array('limit' => 1))
                            ->send();
        if($response->status_code == 200) {
            $content = unserialize($response->content);
            echo '<pre>Users';
            print_r($content);
        }

        $response = $client->setPath('/discussions')
                    ->setQuery(array('limit' => 1))
                    ->send();
        $content = unserialize($response->content);
        print_r($content);

        $response = $client->setPath('/discussions/premiere-communaute/posts')
                    ->setQuery(array('limit' => 1))
                    ->send();
        $content = unserialize($response->content);
        print_r($content);

    }

} catch(BstalkplusClientException $e) {
    echo $e->getMessage();
}