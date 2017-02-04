<?php

require 'Source.php';

abstract class AlertBase
{
    
    protected $_source = null;

    public function __construct(Source $source)
    {

        $this->_source = $source;
    }


    static public function run()
    {   

        global $argv;

        $alert = new static(new Source(self::getStdinData(), $argv));

        $alert->alert();

    }


    static public function getStdinData()
    {

        $fp = fopen('php://stdin', 'r');
        $result = '';

        while(!feof($fp)) {
            $result .= fgets($fp, 128);
        }

        fclose($fp);

        if (!empty($result)) {

            return json_decode($result, true);

        }

        return [];


        //file_put_contents('/tmp/alert_test', $result . print_r($argv, true) .  "\r\n");

    }


    public function getSource()
    {

        return $this->_source;

    }



}