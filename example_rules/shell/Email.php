#!/usr/bin/env php
<?php

require 'AlertBase.php';
require 'vendor/phpmailer/phpmailer/PHPMailerAutoload.php';

class Email extends AlertBase
{


    static public $config = [
        'host' => 'smtp.163.com',
        'port' => '465',
        'username' => '18013905342',
        'password' => 'jdyusltiafklmigt',
        'SMTPSecure' => 'ssl',

        'from' => '18013905342@163.com',
        'fromname' => '来自告警系统的邮件',

        'reply' => 'test@test.com',
        'replyname' => '企业云',

    ];


    static public $emials = [

        '66313856@qq.com' => 'df007df'
    ];


    function sendEmail(array $address, $subject = '', $body = '', $altbody = '', array $attachment = [])
    {


        $mail = new \PHPMailer;

        //$	mail->SMTPDebug = 3;
        // 	Enable verbose debug output
        //$mail->CharSe//$mail->SMTPDebug = 3;                               // Enable verbose debug output
        $mail->CharSet = 'UTF-8';                             // Set CharSet
        $mail->isSMTP();                                      // Set mailer to use SMTP
        $mail->Host = self::$config['host'];               // Specify main and backup SMTP servers
        $mail->Port = self::$config['port'];               // TCP port to connect to
        $mail->SMTPAuth = true;                               // Enable SMTP authentication
        $mail->Username = self::$config['username'];       // SMTP username
        $mail->Password = self::$config['password'];       // SMTP password
        $mail->SMTPSecure = self::$config['SMTPSecure'];   // Enable TLS encryption, `ssl` also accepted

        $mail->setFrom(self::$config['from'], self::$config['fromname']);
        $mail->addReplyTo(self::$config['reply'], self::$config['replyname']);

        $mail->Subject = $subject;
        $mail->Body = $body;

        foreach ($address as $email => $name) {
            $mail->addAddress($email, $name);     // Add a recipient
        }

        foreach ($attachment as $name => $file) {
            $mail->addAttachment($file, $name);
        }

        if ($body) {
            //$mail->isHTML(true);                              // Set email format to HTML
        }

        if ($altbody) {
            $mail->AltBody = $altbody;
        }

        if (!$mail->send()) {
            echo "Message could not be sent. \r\n";
            echo 'Mailer Error: ' . $mail->ErrorInfo . "\r\n";
        } else {
            echo 'Message has been sent.' . "\r\n";
        }

    }




    public function getSendEmail()
    {

        $source = $this->getSource();


        //获取模块，发送对应人

        return self::$emials;

    }

    public function getSendBody()
    {

        $source = $this->getSource();

        /**
         * rule_title
         * rule_text
         * time
         *
         * source
         */

        $ruleTitle = $source->getRuleTitle();
        $ruleText = $source->getRuleText();
        $time = $source->getTime();

        $source = print_r($source->getSource(), true);

        $html =<<<BODY
        rulteTitle: {$ruleTitle}
        ruleText: {$ruleText}
        time: {$time}
        
        source: 
        {$source}

BODY;

        return $html;

    }


    public function getSendTitle()
    {

        return $this->getSource()->getRuleTitle();

    }


    function alert()
    {


        $emails = $this->getSendEmail();


        $title = $this->getSendTitle();


        $this->sendEmail($emails, $title, $this->getSendBody());



    }

}


Email::run();