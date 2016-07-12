# SafeLink

Framework-agnostic, lightweight URL signer. You can use SafeLink to transfer data between projects.

Sign the url in project 1:

```php
use Alfatron\SafeLink;

$safelink = new SafeLink('my-not-short-private-key');
$safelink->redirect('https://second-project/path', ['user' => 'test@example.com', 'action' => 'feed the cat'])
```

Retrieve it in project 2:

```php
use Alfatron\SafeLink;

$safelink = new SafeLink('my-not-short-private-key');
$data = $safeLink->verify();
assert($data['user'], 'test@example.com');
```

## Features

* Uses built-in php serializer to serialize the data to be transferred.
* Can transfer any php type that can be serialized: `object`, `array`, `string`, `integer`.
* Supports php 7.0+.
* Has a default timeout of 10sec.s (customizable).
* Uses `openssl` extension to encrypt the data (`AES-256 CBC`) 

## Installation

Run `composer require ozanhazer/safelink` and you're good to go!

## Options

Timeout is 10sec.s by default to avoid replay attacks. You can change it like:

```php
use Alfatron\SafeLink;

$safeLink = new SafeLink($privateKey, ['timeout' => 2]);
```
