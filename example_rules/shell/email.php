#!/usr/bin/env php
<?php
$fp = fopen('php://stdin', 'r');
$result = '';

while(!feof($fp)) {
    $result .= fgets($fp, 128);
}
fclose($fp);

file_put_contents('/tmp/alert_test', $result . print_r($argv, true) .  "\r\n");

?>
