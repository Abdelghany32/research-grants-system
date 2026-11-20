<?php
declare(strict_types=1);

namespace App\Grants;

/**
 * Money is never a float. Amounts travel as decimal strings ("7000.00"),
 * are stored as numeric(14,2), and are compared as integer minor units.
 */
final class Money
{
    /** Accepts "7000", "7000.5", "7,000.50", "7 000.50". Returns "7000.50" or null. */
    public static function parse(string $input): ?string
    {
        $s = str_replace([' ', ',', "\u{00A0}", "\u{202F}"], '', trim($input));
        if (!preg_match('/^(\d{1,12})(?:\.(\d{1,2}))?$/', $s, $m)) {
            return null;
        }
        return ltrim($m[1], '0') === '' ? '0.' . str_pad($m[2] ?? '', 2, '0') : ltrim($m[1], '0') . '.' . str_pad($m[2] ?? '', 2, '0');
    }

    /** "7000.50" -> 700050 */
    public static function cents(string $canonical): int
    {
        [$whole, $frac] = explode('.', $canonical . '.00');
        return (int) $whole * 100 + (int) str_pad(substr($frac, 0, 2), 2, '0');
    }

    /** 700050 -> "7000.50" */
    public static function fromCents(int $cents): string
    {
        return sprintf('%s%d.%02d', $cents < 0 ? '-' : '', intdiv(abs($cents), 100), abs($cents) % 100);
    }

    /** "7000.5" -> "7,000.50" for display */
    public static function format(string $numeric): string
    {
        $c = self::fromCents(self::cents($numeric));
        [$whole, $frac] = explode('.', $c);
        return preg_replace('/\B(?=(\d{3})+(?!\d))/', ',', $whole) . '.' . $frac;
    }
}
