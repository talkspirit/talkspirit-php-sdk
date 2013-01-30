<?php
/**
* Copyright 2012 blogSpirit,
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may
* not use this file except in compliance with the License. You may obtain
* a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
* License for the specific language governing permissions and limitations
* under the License.
*/

class BstalkplusException extends Exception {
}

abstract class BaseBstalkplusClient {
    /**
     * Error code for Auth
     */
    const AUTH_ERROR_CODE = 6104;

    private $credentials = array();
    private $token = '';
    private $conf = array('config' => array('user_agent' => 'BstalkplusClient'));
    private $support = 'php';
    private $headers = array('Content-Type' => 'application/php', 'Accept' => 'application/php');
    private $data = '';
    private $info = array();
    private $lastRequest;
    private $lastResponse;
    private $lastResponseTime;
    private $url;
    private $lastModified;
    private $query = array();
    protected $cache;

    private $method = 'GET';
    private static $localCache; // used to avoid do many requests when the data are the same
    protected $misses = 0;
    protected $hits = 0;
    protected $hits304 = 0;

    /**
     * @param  $_config
     * @return BstalkplusClient
     */
    function setConfig($_config) {
        if (is_array ($_config)) {
            $this->conf['config'] = array_merge($this->conf['config'], $_config);
        }
        return $this;
    }

    /**
     * @param  $_username
     * @param  $_password
     * @return BstalkplusClient
     */
    function setCredentials($_username, $_password) {
        $this->credentials = array('username' => $_username, 'password' => $_password);
        return $this;
    }

    /**
     *
     * Enter description here ...
     * @param string $_token
     * @return BstalkplusClient
     */
    function setToken($_token) {
        $this->token = $_token;
        return $this;
    }

    /**
     * @param  BstalkplusCache $_cache
     * @return BstalkplusClient
     */
    function setCache($_cache) {
        $this->cache = $_cache;
        return $this;
    }

    function getCache() {
        return $this->cache;
    }

    /**
     * Set the most recent date of modification of the api (@see), must be a timestamp
     */
    function setLastModified($lastModified) {
        $this->_lastModified = $lastModified;
        return $this;
    }

    /**
     * Return the date of the last modification done to the api database.
     *
     * If the lastModified parameter is not set yet, a 'HEAD' request is sent to a special URL that returns
     * the last date of modification.
     * Everytime a non-GET request is sent (ie a modification is done to the api), the lastModified parameter is unset
     *
     * @return mixed
     */
    protected function getLastModified() {
        if (!empty($this->lastModified)) {
            return $this->lastModified;
        } else {
            $response = new BstalkplusHttpResponse;
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $this->conf['config']['api_url']);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "HEAD");
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            curl_setopt($ch, CURLOPT_USERAGENT, $this->conf['config']['user_agent']);
            curl_setopt($ch, CURLOPT_HEADERFUNCTION, array(&$response, 'setHeader'));
            if(!curl_exec($ch)) {
                $response->status = 0;
            }
            if(!empty($this->conf['config']['debug'])) {
                $this->info = curl_getinfo($ch);
                $this->log(round($this->info['total_time'] * 1000) . " ms [" . $response->status_code . "] - HEAD " . $this->conf['config']['api_url']);
            }
            curl_close($ch);
            $this->lastModified = substr($response->headers['Last-Refresh'], 2); // t=xxxx
            return $this->lastModified;
        }
    }

    /**
     * @return current token
     */
    function getCurrentToken() {
        return $this->token;
    }

    /**
     * @return BstalkplusClient
     */
    function bench() {
        $this->conf['config']['bench'] = true;
        return $this;
    }

    /**
     * @param  $_support
     * @return BstalkplusClient
     */
    function setSupport($_support) {
        if($_support == 'php') {
            $this->setHeader('Content-Type', 'application/php');
            $this->setHeader('Accept', 'application/php'); // set the return response
        } else {
            $this->setHeader('Content-Type', 'application/xml');
            $this->setHeader('Accept', 'application/xml');
        }
        return $this;
    }

    /**
     * @return string
     */
    function getSupport() {
        if($this->getHeader('Accept') == 'application/php') {
            return 'php';
        } else {
            return 'xml';
        }
    }

    /**
     * @notes it's better to use setPath (eg parse_url)
     **/
    function setUrl($_url) {
        $this->url  = $this->conf['config']['api_url'] . trim($_url, '/');
        return $this;
    }

    /**
     * @param  $path
     * @return BstalkplusClient
     */
    function setPath($path) {
        return $this->setUrl($path);
    }

    /**
     * @param  $_etag
     * @return BstalkplusClient
     */
    function setEtag($_etag) {
        $this->setHeader('If-None-Match', '"' . $_etag . '"');
        return $this;
    }

    protected function removeEtag() {
        return $this->removeHeader('If-None-Match');
    }

    /**
     * @return string
     */
    function getUrl() {
        $p = parse_url($this->url);
        $str = $p['scheme'] . '://' . $p['host'] . $p['path'] . $this->getQueryString();
        return $str;
    }

    /**
     * @throws Exception
     * @param  $_filename
     * @return BstalkplusClient
     */
    function setFile($_filename) {
        if(!function_exists('finfo_open')) {
            throw new Exception("finfo must be setup.");
        }
        $finfo = finfo_open(FILEINFO_MIME);
        $m = finfo_file($finfo, $_filename);
        finfo_close($finfo);
        $this->headers['Content-Type'] = $m;
        $this->headers['Slug'] = basename($_filename);
        $this->setData(base64_encode(file_get_contents($_filename)));
        return $this;
    }

    /**
     * @param  $_data
     * @return BstalkplusClient
     */
    function setData($_data) {
        $data = trim($_data);
        if($this->headers['Content-Type'] == 'application/xml') {
            if(!empty($data) && strpos($data, '<?xml') === false) {
                $this->data = '<?xml version="1.0" encoding="utf-8"?>' . $data;
            } else {
                $this->data = $data;
            }
        } else { // suppose that we use PHP or json
            $this->data = $data;
        }
        return $this;
    }

    /**
     * @param  $_method
     * @return BstalkplusClient
     */
    function setMethod($_method) {
        $this->method = strtoupper($_method);
        return $this;
    }

    /**
     * @param  $_key
     * @param  $_value
     * @return BstalkplusClient
     */
    function setHeader($_key, $_value) {
        $this->headers[$_key] = $_value;
        return $this;
    }

    /**
     * @param  $_header
     * @return array|null
     */
    function getHeader($_header) {
        if(isset($this->headers[$_header])) {
            return $this->headers[$_header];
        } else {
            return null;
        }
    }

    /**
     * @return array
     */
    function getInfo() {
        return $this->info;
    }

    /**
     * @return void
     */
    function resetHeaders() {
        $this->headers = array('Content-Type' => 'application/php', 'Accept' => 'application/php');
        $this->query = array();
    }

    protected function removeHeader($_header) {
        if($this->headers[$_header]) {
            unset($this->headers[$_header]);
            return true;
        } else {
            return false;
        }
    }

    /**
     *
     */
    public function connectUser($user, $password = null) {
        if($user != null && $password != null) {
            $this->setCredentials($user, $password);
            $token = $this->getToken(false);
            if($token !== false) {
                $this->setToken($token);
                return $token;
            } else {
                return false;
            }
        } elseif(is_array($user) && isset($user['sso'])) { // sso connection
            if(!isset($user['sso']['name']) || !isset($user['sso']['key'])) {
                return false;
            }
            $this->setCredentials($user['sso']['key'], (isset($user['sso']['password']) ? $user['sso']['password'] : ''));
            $this->setHeader('SSO', $user['sso']['name']);
            $token = $this->getToken(false);
            if($token !== false) {
                $this->setToken($token);
                return $token;
            } else {
                return false;
            }
        } elseif($user != null) { // if password not passed, we assume it is the token, test
            if(strlen($user) == 1) {//on a un token = a 1 ou 2
                $token = $this->getToken(false);
                if($token !== false) {
                    $this->setToken($token);
                    return $token;
                }
            } else {
                $this->setToken($user);
                return $user;
            }
        }
    }

    /**
     * @return
     */
    function getLastResponse() {
        return $this->lastResponse;
    }

    /**
     * @return
     */
    function getLastRequest() {
        return $this->lastRequest;
    }

    /**
     * @param bool $backup
     * @return bool|string
     */
    function getToken($backup = true) {
        if(isset($this->token[0]) && $backup == true) {
            if (strlen($this->token) == 1) {
                $this->log('Token is set, backup is true and token is equal to ' . $this->token);
            }
            return $this->token;
        }
        if (empty ($this->credentials) && !(empty ($this->token))) {
            if (strlen($this->token) == 1) {
                $this->log('Token is already set session and equal to ' . $this->token);
            }
            return $this->token;
        }
        $response = new BstalkplusHttpResponse;
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->conf['config']['api_url']. 'access_token');
        $headers = array();
        $headers[] = 'Content-Type: application/xml';
        $headers[] = "Consumer-Key: " . $this->conf['config']['consumer_key'];
        $headers[] = "content-length: 0"; // fix bug with 5.3.3
        foreach($this->headers as $k => $v) {
            if(in_array($k, array('SSO'))) {
                $headers[] = $k . ": " . $v; // added for sso connection headers
            }
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_setopt($ch, CURLOPT_USERPWD, $this->credentials['username'] .':' . $this->credentials['password']);
        curl_setopt($ch, CURLOPT_USERAGENT, $this->conf['config']['user_agent']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, array(&$response, 'setHeader'));
        curl_setopt($ch, CURLOPT_WRITEFUNCTION, array(&$response, 'setContent'));

        if(isset($this->conf['config']['proxy_url'])) {
            curl_setopt($ch, CURLOPT_PROXY, $this->conf['config']['proxy_url']);
            curl_setopt($ch, CURLOPT_PROXYPORT, $this->conf['config']['proxy_port']);
            if(isset($this->conf['config']['proxy_userpwd'])) {
                curl_setopt($ch, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);
                curl_setopt ($ch, CURLOPT_PROXYUSERPWD, $this->conf['config']['proxy_userpwd']);
            }
        }
        if(!curl_exec($ch)) {
            $response->status = 0;
        }
        if(!empty($this->conf['config']['debug'])) {
            $this->info = curl_getinfo($ch);
            $this->info['requestheaders'] = $headers;
            $this->log(round($this->info['total_time'] * 1000) . " ms [" . $response->status_code . "] - POST " . $this->conf['config']['api_url'] . 'access_token');
        }
        if(strpos($response->content, 'oauth_token') !== false) {
            $this->token = substr($response->content, strlen('oauth_token='));
            curl_close($ch);
            return $this->token;
        } else {
            $this->info = curl_getinfo($ch);
            $this->lastResponse = $response;
            $this->lastResponseTime = time();
            curl_close($ch);
            return false;
        }
    }

    /**
     * @return BstalkplusHttpResponse
     */
    function send() {
        /*if (! (isset($this->method))) {
            // Something wrong happened
            $trace = debug_backtrace();
            foreach ($trace as $i=>$t) {
                $log = $i .'=>'.$t['file'].' '.$t['line']."\n";
            }
            Logger::Warn ($log);
        }*/
        switch ($this->method) {
            case 'GET':
                return $this->checkCache();
            default :
                //On POST, PUT or DELETE, emptying lastModified and localCache
                self::$localCache = array();
                unset($this->lastModified);
                return $this->sendGeneric();
        }
    }

    private function getMicrotime() {
        return (int) round(microtime(true) * 1000, 0);
    }

    /**
     * @throws BstalkplusException
     * @return BstalkplusHttpResponse
     */
    protected function checkCache() {
        if(!$this->cache) {
            $this->log('No cache configured');
            return $this->sendGeneric(); // no cache at all
        }
        if(empty($this->token)) {
            throw new BstalkplusException('The caching system needs a token', 6104);
        }

        $key = md5($this->token . $this->getHeader('Content-Type') . $this->getUrl());

        if(isset(self::$localCache[$key])) {
            return self::$localCache[$key];
        }

        /**
         * We check if the content is set
         */
        $cachedValue = $this->cache->get($key);
        if (isset($cachedValue['content']) && $cachedValue['content']->content != '') {
            $lastModified = $this->getLastModified();
            // If last modify time is before creation
            if($lastModified < (int) $cachedValue['created']) {
                self::$localCache[$key] = $cachedValue['content'];
                $this->hits++;
                return $cachedValue['content'];
            }
            /** Get the previous etag **/
            $eTag = trim($cachedValue['eTag'], '"');
            $this->setETag($eTag);
            $response = $this->sendGeneric();
            /** If the code is 304, means that the previous query is in cache */
            if((int) $response->status_code == 304) {
                $this->hits304++;
                //updating created in cache
                $newCachedValues = array(
                    'eTag' => $eTag,
                    'created' => $this->getMicrotime(),
                    'content' => $cachedValue['content'],
                );
                $this->cache->set($key, $newCachedValues);
                // updating local cache
                self::$localCache[$key] = $cachedValue['content'];
                // returning cached content
                return $cachedValue['content'];
            } else if(isset($response->headers['ETag'])) {
                $this->misses++;
                $newCachedValues = array(
                    'eTag' => $response->headers['ETag'],
                    'created' => $this->getMicrotime(),
                    'content' => $response,
                );
                $this->cache->set($key, $newCachedValues);
                self::$localCache[$key] = $response;
            }
            return $response;
        }

        // Avoid 304 response, force to get a new request
        $this->removeEtag();
        $response = $this->sendGeneric();

        if((int) $response->status_code == 200 && isset($response->headers['ETag'])) {
            if ($response->content == '') {
                // We don't set in cache an empty content
                logger::warn($this->url.' return an empty content');
            } else {
                $newCachedValues = array(
                    'eTag' => $response->headers['ETag'],
                    'created' => $this->getMicrotime(),
                    'content' => $response,
                );
                $this->cache->set($key, $newCachedValues);
                self::$localCache[$key] = $response;
            }
        }
        return $response;
    }

    function setQuery($_arr = array()) {
        $this->query = $_arr;
        return $this;
    }

    function getQueryString() {
        $p  = parse_url($this->url);
        if(!isset($p['query'])) {
            $p['query'] = '';
        }
        parse_str($p['query'], $output);
        if (isset ($this->query)) {
            $query = array_merge($output, $this->query);
        } else {
            $query = $output;
        }
        $str = http_build_query($query);
        if(!empty($str)) {
            return '?' . $str;
        } else {
            return $str;
        }
    }

    /**
     * @return BstalkplusHttpResponse
     **/
    function sendGeneric() {
        if(!empty($this->conf['config']['bench'])) {
            $time_start = microtime(true);
        }
        $ch = curl_init();
        $p  = parse_url($this->url);
        $query = $this->getQueryString();
        $headers = array();
        switch($this->method) {
            case 'GET':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "GET");
                break;
            case 'PUT':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
                break;
            case 'POST':
                curl_setopt($ch, CURLOPT_POST, true);
                break;
            case 'DELETE':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
        }

        foreach($this->headers as $k => $v) {
            $headers[] = $k . ": " . $v; // try to fix bug
        }

        if ($this->conf['config']['consumer_key'] == '' || empty ($this->conf['config']['consumer_key'] )) {
            throw new BstalkplusException('Consumer_key is missing or empty', 6105);
        }

        $headers[] = "Consumer-Key: ".$this->conf['config']['consumer_key']; /** authenticate the client **/
        $auth_attributes['token'] = $this->getToken();
        $auth_attributes['class'] = 'oauth';
        $auth_attributes['method'] = 'hmac-sha-1';
        $auth_attributes['timestamp'] = time();
        $auth_attributes['nonce'] = md5(uniqid(rand(), true));


        $str = '';
        $str2 = '';
        foreach($auth_attributes as $k => $v) {
            $str .= "$k=\"$v\",";
        }
        ksort($auth_attributes);
        foreach($auth_attributes as $k => $v) {
            $str2 .= "$k=$v,";
        }

        $digest = "$this->method," . $p['host'] . ':80,'.$str2 . $this->conf['config']['consumer_secret'] . ',' . $p['path'] . $query;
        $auth = sha1($digest);
        $headers[] = "Authorization: Token $str auth=\"$auth\"";
        if($this->data) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $this->data);
        }

        if(isset($this->conf['config']['debugmore'])) {
            curl_setopt($ch, CURLOPT_VERBOSE, true);
            $handler = fopen(PROJECT_DIR . 'logs/access_log', 'a');
            curl_setopt($ch, CURLOPT_STDERR, $handler);
        }
        $response = new BstalkplusHttpResponse;
        curl_setopt($ch, CURLOPT_URL, "http://" . $p['host'] . $p['path'] . $query);
        curl_setopt($ch, CURLOPT_USERAGENT, $this->conf['config']['user_agent']);
        curl_setopt($ch, CURLOPT_ENCODING, 'deflate');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_TIMEOUT, 60);
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, array(&$response, 'setHeader'));
        curl_setopt($ch, CURLOPT_WRITEFUNCTION, array(&$response, 'setContent'));

        if(isset($this->conf['config']['proxy_url'])) {
            curl_setopt($ch, CURLOPT_PROXY, $this->conf['config']['proxy_url']);
            curl_setopt($ch, CURLOPT_PROXYPORT, $this->conf['config']['proxy_port']);
            if(isset($this->conf['config']['proxy_userpwd'])) {
                curl_setopt($ch, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);
                curl_setopt($ch, CURLOPT_PROXYUSERPWD, $this->conf['config']['proxy_userpwd']);
            }
        }
        if(!curl_exec($ch)) {
            $response->status = 0;
        }

        $this->lastResponse = $response;
        $this->lastResponseTime = time();
        if(!empty($this->conf['config']['debug'])) {
            $this->info = curl_getinfo($ch);
            $this->info['requestheaders'] = $headers;
            $this->log(round($this->info['total_time'] * 1000) . " ms [" . $response->status_code . "] - " . $this->method . " http://".$p['host'] . $p['path'] . $query);
        }
        if(!empty($this->conf['config']['bench'])) {
            $time = microtime(true) - $time_start;
            echo "\033[1;31m";
            echo "Request in " . round($time, 3) . " seconds" . PHP_EOL;
            echo "\033[1;0m";
        }
        if(in_array($response->status_code, array(400, 404, 406, 503))) {
            $c = curl_getinfo($ch);
            $this->log('Url (' . $c['url'] . ') ' . $response->content);
            if($response->status_code == 406) {
                // clear the session, next time get a new token
                $this->disconnectUser();
            }
        }
        curl_close($ch);
        return $response;
    }

    protected function log() {
        // implement the logger in subclass
    }

    function disconnectUser() {
    }
}

class BstalkplusHttpResponse {
    public $content = '';
    public $status_line = '';
    public $status_code = '';
    public $headers = array();

    function setContent($_fp, $_content) {
        $this->content .= $_content;
        return strlen($_content);
    }

    function setHeader($_fp, $_header) {
        if(($pos = strpos($_header, ':')) === false) {
            if(substr($_header, 0, 4) == 'HTTP') {
                $pattern = "!HTTP/(\d\.\d) (\d+) (.*)!";
                if(preg_match($pattern, $_header, $tags)) {
                    $this->version = $tags[1];
                    $this->status_code = (int) $tags[2];
                    $this->status_line = $tags[3];
                }
            } else {
                $this->others = $_header;
            }
        } else {
            $k = substr($_header, 0, $pos);
            $v = substr($_header, $pos + 2);
            $this->headers[$k] = trim($v);
        }
        return strlen($_header);
    }

    /**
     *  @SuppressWarnings(PHPMD.PHPMD.UnusedPrivateMethod)
     */
    private function _headers($_v, $_k) {
        echo "$_k$_v" . PHP_EOL;
    }

    function __toString() {
        echo "Headers : " . PHP_EOL;
        echo "Status: $this->status_code $this->status_line" . PHP_EOL;
        array_walk($this->headers, array($this, '_headers'));

        echo PHP_EOL . "Content : ". PHP_EOL;
        if(substr($this->content, 0, 5) == '<?xml') {
            $doc = new DOMdocument("1.0");
            $doc->loadxml($this->content);
            $doc->formatOutput = true;
            echo $doc->saveXML();
        } else {
            echo $this->content;
        }
        echo PHP_EOL;
    }
}