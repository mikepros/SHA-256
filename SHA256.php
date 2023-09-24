<?php declare(strict_types=1);

/*******************************************************************************
 *
 * Implementation of SHA-256 algorithm of FIPS 180-4 specificated on
 * @link https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 * Version 1.0
 * PHP version >= 8.1
 *
 ******************************************************************************/

/*
 * Usage: SHA256::hash('Your message');
 */
final class SHA256
{
    /*
     * @const array[string => int] H Initial working variables and hash values
     * @const int[] K Integers used to update working variables
     */
    private const
        H = [
            'a' => 0x6a09e667, 'b' => 0xbb67ae85, 'c' => 0x3c6ef372, 'd' => 0xa54ff53a,
            'e' => 0x510e527f, 'f' => 0x9b05688c, 'g' => 0x1f83d9ab, 'h' => 0x5be0cd19,
        ],
        K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];

    /*
     * Main method
     */
    public static function hash(string $M): string
    {
        $hash = '';

        // Add padding to the message
        $l = \mb_strlen($M); // Length of message
        $M .= \chr(0x80); // Append bit "1" and seven zero bits
        // $k is the smallest, non-negative solution to the equation l + 1 + k === 56 mod 64
        $k = 56 - (($l1_mod64 = ($l + 1) % 64) > 56 ? $l1_mod64 - 64 : $l1_mod64);
        $M .= \str_repeat(\chr(0), $k); // Append $k zero bytes to message $M
        $M .= \pack('J', $l * 8); // Append message length in bits to the end

        // Split message with padding into 64-byte blocks
        $blocks = \mb_str_split($M, 64);

        $hash_values = self::compress($blocks);

        // Implode hash values and return 256-bit message digest
        foreach ($hash_values as $value)
            $hash .= \sprintf('%08x', $value);

        return $hash;

    }

    /*
     * Compress all 64-byte blocks
     * @note Modulo 2^32 is performed on any addition operation
     */
    private static function compress(array $blocks): array
    {
        // Init message schedule
        $W = [];

        // Init hash values and working variables
        \extract($buffer = self::H);

        foreach ($blocks as $block) {
            for($i = 0; $i < 64; $i++) {

                // Compute 32-bit word of message schedule
                if ($i < 16) {
                    $W[$i] = (\ord($block[$i*4]) & 0xFF) << 8;
                    $W[$i] = ($W[$i] | (\ord($block[$i * 4 + 1]) & 0xFF)) << 8;
                    $W[$i] = ($W[$i] | (\ord($block[$i * 4 + 2]) & 0xFF)) << 8;
                    $W[$i] = $W[$i] | (\ord($block[$i * 4 + 3]) & 0xFF);
                } else {
                    $W[$i] = (self::σ1($W[$i - 2]) + $W[$i - 7] + self::σ0($W[$i - 15]) + $W[$i - 16]) & 0xffffffff;
                }

                // Update working variables
                $T1 = ($h + self::Σ1($e) + self::Ch($e, $f, $g) + self::K[$i] + $W[$i]) & 0xffffffff;
                $T2 = (self::Σ0($a) + self::Maj($a, $b, $c)) & 0xffffffff;
                $h = $g;
                $g = $f;
                $f = $e;
                $e = ($d + $T1) & 0xffffffff;
                $d = $c;
                $c = $b;
                $b = $a;
                $a = ($T1 + $T2) & 0xffffffff;
            }

            // Concatenate current hash values with previous
            for($i = 'a'; $i <= 'h'; $i++)
                $$i = $buffer[$i] = ($$i + $buffer[$i]) & 0xffffffff;
        }

        return $buffer;
    }

    // Logical functions
    private static function RotR(int $n, int $x): int { return (($x >> $n) & 0xFFFFFFFF) | ($x << (32 - $n)); }
    private static function Σ0(int $x): int { return self::RotR(2, $x) ^ self::RotR(13, $x) ^ self::RotR(22, $x); }
    private static function Σ1(int $x): int { return self::RotR(6, $x) ^ self::RotR(11, $x) ^ self::RotR(25, $x); }
    private static function σ0(int $x): int { return self::RotR(7,  $x) ^ self::RotR(18, $x) ^ (($x >> 3) & 0xFFFFFFFF); }
    private static function σ1(int $x): int { return self::RotR(17, $x) ^ self::RotR(19, $x) ^ (($x >> 10) & 0xFFFFFFFF); }
    private static function Ch(int $x, int $y, int $z): int  { return ($x & $y) ^ (~$x & $z); }
    private static function Maj(int $x, int $y, int $z): int { return ($x & $y) ^ ($x & $z) ^ ($y & $z); }
}
