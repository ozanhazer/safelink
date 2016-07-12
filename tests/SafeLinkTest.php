<?php

namespace Alfatron\SafeLink\Tests;

use Alfatron\SafeLink\InvalidArgumentException;
use Alfatron\SafeLink\Response;
use Alfatron\SafeLink\SafeLink;
use Alfatron\SafeLink\VerificationException;
use PHPUnit\Framework\TestCase;

class SafeLinkTest extends TestCase
{
    /**
     * @test
     */
    public function it_can_be_initialized_from_constructor()
    {
        $secretKey = 'somerandomkey' . uniqid();

        $safeLink = new SafeLink($secretKey);

        $this->assertEquals($safeLink->getSecretKey(), $secretKey);
    }

    /**
     * @test
     */
    public function it_encrypts_and_decrypts_consistently()
    {
        $safeLink = new SafeLink();
        $safeLink->setSecretKey('somerandomkey' . uniqid());

        $someObj = new \stdClass();
        $someObj->test = 'deneme';

        $datas = [
            true,
            false,
            'test',
            $someObj,
            0,
            1,
            [1, 2, 3],
            ['string', $someObj, ['123', 2]],
        ];

        foreach ($datas as $data) {
            $enc = $safeLink->encrypt($data);
            $iv = $safeLink->getIV();

            $this->assertEquals($data, $safeLink->decrypt($enc, $iv));
        }
    }

    /**
     * @test
     */
    public function it_validates_secret_key()
    {
        $this->expectException(InvalidArgumentException::class);
        $safeLink = new SafeLink();
        $safeLink->setSecretKey(uniqid());
    }

    /**
     * @test
     */
    public function it_can_reveal_the_secret_key()
    {
        $key = '12341234112341234';

        $safeLink = new SafeLink();
        $safeLink->setSecretKey($key);
        $this->assertSame($key, $safeLink->getSecretKey());
    }

    /**
     * @test
     */
    public function it_creates_IV_if_not_existed()
    {
        $safeLink = new SafeLink();
        $this->assertNotEmpty($safeLink->createGetIV());
    }

    /**
     * @test
     */
    public function it_should_not_create_IV_if_already_exists()
    {
        $iv = '1234567890123456';

        $safeLink = new SafeLink();
        $safeLink->setIV('1234567890123456');
        $this->assertSame($iv, $safeLink->createGetIV());
    }

    /**
     * @test
     */
    public function it_should_check_IV_length()
    {
        $this->expectException(VerificationException::class);

        $safeLink = new SafeLink();

        $iv = '1234';
        $safeLink->setIV($iv);

        $iv = '12345678901234567890';
        $safeLink->setIV($iv);
    }

    /**
     * @test
     */
    public function it_should_return_response_when_verified()
    {
        $safeLink = new SafeLink();
        $safeLink->setSecretKey('1234123412341234');

        $data = 'deneme';
        $ts = time();

        $encData = $safeLink->encrypt([
            'data' => $data,
            'ts' => $ts,
        ]);

        $iv = $safeLink->getIV();

        $_GET['i'] = $iv;
        $_GET['s'] = $encData;

        $this->assertInstanceOf(Response::class, $safeLink->verify());
    }

    // TODO: Test options
}