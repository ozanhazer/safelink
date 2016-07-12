<?php

namespace Alfatron\SafeLink;

class Response
{
    /**
     * Encrypted data
     * @var mixed
     */
    public $data;

    /**
     * The time request is signed (unix timestamp)
     * @var integer
     */
    public $timestamp;
}