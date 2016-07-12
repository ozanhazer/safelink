<?php

require 'vendor/autoload.php';

use Alfatron\SafeLink\SafeLink;

$safeLink = new SafeLink();
$safeLink->setSecretKey('1234123412341234');
$safeLink->redirect('https://stars2.bilkent.edu.tr', ['sicilno' => 7152]);

$safeLink = new SafeLink('1234123412341234');
$safeLink->redirect('https://stars2.bilkent.edu.tr', ['sicilno' => 7152]);

$safeLink = new SafeLink();
$safeLink->setSecretKey('1234123412341234');
$data = $safeLink->verify();

$safeLink = new SafeLink('1234123412341234');
$data = $safeLink->verify();