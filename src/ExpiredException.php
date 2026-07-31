<?php

namespace Firebase\JWT;

class ExpiredException extends \UnexpectedValueException implements JWTExceptionWithPayloadInterface
{
    private object $payload;

    private int|float|null $timestamp = null;

    public function setPayload(object $payload): void
    {
        $this->payload = $payload;
    }

    public function getPayload(): object
    {
        return $this->payload;
    }

    /**
     * @param int|float $timestamp Seconds, or milliseconds when
     *                             JWT::$useMillisecondTimestamps is enabled.
     */
    public function setTimestamp(int|float $timestamp): void
    {
        $this->timestamp = $timestamp;
    }

    public function getTimestamp(): int|float|null
    {
        return $this->timestamp;
    }
}
