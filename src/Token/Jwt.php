<?php

declare(strict_types=1);

namespace MechtaMarket\AuthClient\Token;

use DateTimeInterface;
use DomainException;
use MechtaMarket\AuthClient\Exception\BeforeValidException;
use MechtaMarket\AuthClient\Exception\ExpiredException;
use stdClass;
use UnexpectedValueException;

use function base64_decode;
use function count;
use function date;
use function explode;
use function is_null;
use function json_decode;
use function json_last_error;
use function str_repeat;
use function strlen;
use function strtr;
use function time;

final class Jwt
{
    public static int $leeway = 30;
    public static ?int $timestamp = null;

    public static function decode(string $token): stdClass
    {
        $timestamp = is_null(static::$timestamp) ? time() : static::$timestamp;
        $tks = explode('.', $token);
        if (count($tks) !== 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }
        $payloadRaw = static::urlsafeB64Decode($tks[1]);
        $payload = static::jsonDecode($payloadRaw);
        if (!$payload instanceof stdClass) {
            throw new UnexpectedValueException('Payload must be a JSON object');
        }

        if (isset($payload->nbf) && floor($payload->nbf) > ($timestamp + static::$leeway)) {
            throw new BeforeValidException(
                'Cannot handle token with nbf prior to ' . date(DateTimeInterface::ATOM, (int) $payload->nbf),
            );
        }

        if (!isset($payload->nbf) && isset($payload->iat) && floor($payload->iat) > ($timestamp + static::$leeway)) {
            throw new BeforeValidException(
                'Cannot handle token with iat prior to '
                . date(DateTimeInterface::ATOM, (int) $payload->iat)
                . ' because current time is '
                . date(DateTimeInterface::ATOM, (int) ($timestamp + static::$leeway)),
            );
        }

        if (isset($payload->exp) && ($timestamp - static::$leeway) >= $payload->exp) {
            throw new ExpiredException('Expired token');
        }

        return $payload;
    }

    private static function jsonDecode(string $input): object
    {
        $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);

        if ($errno = json_last_error()) {
            self::handleJsonError($errno);
        } elseif ($obj === null && $input !== 'null') {
            throw new DomainException('Null result with non-null input');
        }
        return $obj;
    }

    private static function handleJsonError(int $errno): void
    {
        $messages = [
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
            JSON_ERROR_UTF8 => 'Malformed UTF-8 characters',
        ];
        throw new DomainException(
            $messages[$errno] ?? 'Unknown JSON error: ' . $errno,
        );
    }

    public static function urlsafeB64Decode(string $input): string
    {
        return base64_decode(self::convertBase64UrlToBase64($input));
    }

    public static function convertBase64UrlToBase64(string $input): string
    {
        if ($remainder = strlen($input) % 4) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return strtr($input, '-_', '+/');
    }
}
