<?php
namespace RandomTool;

use Exception;

class RandomEncrypt
{
    /** @var int 北京时间时区信息 */
    private int $timezoneOffset = 8;

    /** @var int key有效期（单位秒） */
    private int $timeInterval = 5;

    private int $options = OPENSSL_RAW_DATA;

    /** @var int key 加密key长度 */
    private int $keyLength = 16;

    /** @var int 如果跨区间 冗余几秒 */
    private int $secondRedundancy = 2;

    /** @var int 当前时区（北京/东八区）时间戳 */
    private int $timestamp = 0;

    /** @var string 自定义盐值 */
    private string $salt = "";

    private array $map = [
        "1" => '#',
        "2" => '0',
        "3" => '*',
        "4" => '9',
        "5" => '8',
        "6" => '7',
        "7" => '6',
        "8" => '5',
        "9" => '4',
        "*" => '3',
        "0" => '2',
        "#" => '1',
    ];

    private array $cipherAlgoMap = [
        0 => "AES-128-CBC",
        1 => "ARIA-128-CTR",
        2 => "CAMELLIA-128-CBC",
        3 => "SEED-CBC",
        4 => "SM4-CBC",
        5 => "AES-128-CBC-HMAC-SHA256",
    ];

    /**
     * 如果不是依赖注入到方法参数中
     * 使用静态方法完成实例化
     * RandomEncrypt::init(["salt" => "salt"])->encrypt($str);
     * RandomEncrypt::init(["salt" => "salt"])->decrypt($en_str);
     * @param array $config
     * @return RandomEncrypt
     */
    public static function init(array $config = []): RandomEncrypt
    {
        $e = new self;
        $e->config($config);
        return $e;
    }

    private function getCipherAlgo(): string
    {
//        $intervalIndex = ceil($this->timestamp / $this->timeInterval);
//        return $this->cipherAlgoMap[$intervalIndex % count($this->cipherAlgoMap)];
        // 浏览器用
        return $this->cipherAlgoMap[0];
    }

    private function getTimeGroup(int $timestamp): int
    {
        return ceil($timestamp / $this->timeInterval) * $this->timeInterval;
    }

    private function getCurrentTimezoneOffset(): int
    {
        $d = new \DateTime();
        return $d->getOffset() / 3600;
    }

    private function formatDateTime(int $timestamp): string
    {
        $offset = $this->getCurrentTimezoneOffset();
        $timestamp += ($this->timezoneOffset - $offset) * 3600;
        return date("YmdHis", $timestamp);
    }

    /**
     * @throws Exception
     */
    private function key(int $timestamp = 0): array
    {
        if ($timestamp === 0) {
            $timestamp = time();
        }
        $this->timestamp = $timestamp;
        $timestamp = $this->getTimeGroup($timestamp);
        $datetime = $this->formatDateTime($timestamp);
        $arr = str_split($datetime);
        $key = implode("", array_map(function ($v) {
            return $this->map[$v];
        }, $arr));
        $index = $datetime % $this->keyLength;
        $passphrase = $datetime . $key . $datetime;
        $iv = $key . $datetime . $key;
        return [$this->getEncryptKey($passphrase, $index), $this->getEncryptKey($iv, $index)];
    }

    /**
     * @throws Exception
     */
    private function getEncryptKey(string $str, int $index): string
    {
        if ($this->salt === "") {
            throw new Exception("the salt can not be empty.");
        }
        return strtolower(substr(md5($str . $this->salt), $index, $this->keyLength));
    }

    /**
     * 加密函数
     * @throws Exception
     */
    public function encrypt(string $string): array
    {
        $key = $this->key();
        $encrypt = openssl_encrypt($string, $this->getCipherAlgo(), $key[0], 0, $key[1]);
        return [$encrypt, ...$key, $this->timestamp];
    }

    /**
     * 解密函数
     * @throws Exception
     */
    public function decrypt(string $string): string
    {
        $current = time();
        $rs = $this->doDecrypt($string);
        if ($rs === "" && $this->isReDecrypted($current)) {
            $rs = $this->doDecrypt($rs, $current - $this->timeInterval);
        }
        return $rs;
    }

    /**
     * 如果跨时区 判断是否可以重新解密
     * @param int $current
     * @return bool
     */
    private function isReDecrypted(int $current): bool
    {
        return $current % $this->timeInterval <= $this->secondRedundancy;
    }

    /**
     * 指定时间解密
     * @param string $string
     * @param int $timestamp
     * @return string
     * @throws Exception
     */
    public function doDecrypt(string $string, int $timestamp = 0): string
    {
        $key = $this->key($timestamp);
        $rs = openssl_decrypt($string, $this->getCipherAlgo(), $key[0], 0, $key[1]);
        return trim($rs);
    }


    /**
     * 指定key,iv解密
     * @param string $string
     * @param string $key
     * @param string $iv
     * @return string
     */
    public function decryptByKeyIv(string $string, string $key, string $iv): string
    {
        $rs = openssl_decrypt(base64_decode($string), $this->getCipherAlgo(), $key, $this->options, $iv);
        return trim($rs);
    }

    /**
     * 自定义盐值 加密时不能为空
     * @param string $salt
     * @return $this
     */
    public function setSalt(string $salt): self
    {
        $this->salt = $salt;
        return $this;
    }

    /**
     * 自定义对齐时区 默认东八区
     * @param int $offset
     * @return $this
     */
    public function setTimezoneOffset(int $offset): self
    {
        $this->timezoneOffset = $offset;
        return $this;
    }

    /**
     * 自定义加密key有效时间 默认5秒
     * key有效期为 timeInterval + secondRedundancy
     * @param int $timeInterval
     * @return $this
     */
    public function setTimeInterval(int $timeInterval): self
    {
        $this->timeInterval = $timeInterval;
        return $this;
    }

    /**
     * 自定义跨区间 冗余秒数 默认2秒
     * key有效期为 timeInterval + secondRedundancy
     * @param int $secondRedundancy
     * @return $this
     */
    public function setSecondRedundancy(int $secondRedundancy): self
    {
        $this->secondRedundancy = $secondRedundancy;
        return $this;
    }

    /**
     * 自定义设置参数
     * @param array $config ['salt' => '', 'offset' => 10, 'timeInterval' => 7, 'secondRedundancy' => '3']
     * @return $this
     */
    public function config(array $config): self
    {
        if (isset($config['salt'])) {
            $this->setSalt($config['salt']);
        }
        if (isset($config['offset'])) {
            $this->setTimezoneOffset((int)$config['offset']);
        }
        if (isset($config['timeInterval'])) {
            $this->setTimeInterval((int)$config['timeInterval']);
        }
        if (isset($config['secondRedundancy'])) {
            $this->setSecondRedundancy((int)$config['secondRedundancy']);
        }
        return $this;
    }
}