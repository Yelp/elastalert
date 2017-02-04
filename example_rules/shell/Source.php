<?php

class Source 
{


    private $_matchs = [];

    private $_args = [];

    public function __construct($matchs = [], $args = [])
    {
        $this->_matchs = $matchs;
        $this->_args = $args;
    }


    //获取报警原始数据
    public function getSource($field = false)
    {

        if (isset($this->_matchs[0])) {

            if ($field) {
                if (isset($this->_matchs[0][$field])) {
                    return $this->_matchs[0][$field];
                }

            } else {
                return $this->_matchs[0];
            }
        }

        return null;
    }


    public function getArgs()
    {

        return $this->_args;

    }

    //获取规则描述信息
    public function getRuleText()
    {

        return $this->getSource('elastalert_rule_text');

    }


    //获取规则标题
    public function getRuleTitle()
    {

        return $this->getSource('elastalert_subject_title');

    }

    //获取规则事件时间
    public function getTime()
    {

        return $this->getSource('time');
    }


}