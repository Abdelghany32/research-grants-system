<?php
declare(strict_types=1);

namespace App\Http;

/** Plain PHP templates. Templates only print; they never query the database. */
final class View
{
    private const DIR = __DIR__ . '/../../templates/';

    /** Render templates/<name>.php inside the shared layout. */
    public static function page(string $name, array $data): string
    {
        $data['content'] = self::partial($name, $data);
        return self::partial('layout', $data);
    }

    public static function partial(string $name, array $data): string
    {
        extract($data, EXTR_SKIP);
        ob_start();
        require self::DIR . $name . '.php';
        return (string) ob_get_clean();
    }
}
