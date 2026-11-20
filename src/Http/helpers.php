<?php
declare(strict_types=1);

use App\Grants\Money;

/** Escape for HTML text and attribute values. Every dynamic value in a template passes through this. */
function e(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** "7000.5" -> "7,000.50" */
function money(?string $numeric): string
{
    return $numeric === null ? '' : Money::format($numeric);
}

/** One consistent UTC date format everywhere: 2026-11-30 23:59 UTC */
function utc(?string $timestamp, bool $withTime = true): string
{
    if ($timestamp === null || $timestamp === '') {
        return '';
    }
    $d = new DateTimeImmutable($timestamp);
    $d = $d->setTimezone(new DateTimeZone('UTC'));
    $text = $d->format($withTime ? 'Y-m-d H:i' : 'Y-m-d') . ($withTime ? ' UTC' : '');
    return '<time datetime="' . e($d->format('c')) . '">' . e($text) . '</time>';
}

/** Status label: always text plus a shape, colour is only reinforcement. */
function status_badge(string $status): string
{
    $labels = [
        'draft' => 'Draft', 'submitted' => 'Submitted', 'under_review' => 'Under review',
        'approved' => 'Approved', 'declined' => 'Declined',
        'assigned' => 'Awaiting review', 'open' => 'Open', 'closed' => 'Closed',
        'success' => 'Success', 'denied' => 'Denied', 'failure' => 'Failure',
    ];
    return '<span class="badge badge-' . e($status) . '">' . e($labels[$status] ?? $status) . '</span>';
}

function icon(string $name): string
{
    return '<svg class="icon" aria-hidden="true" focusable="false"><use href="/assets/icons/sprite.svg#' . e($name) . '"></use></svg>';
}

function field_error(array $errors, string $field): string
{
    return isset($errors[$field])
        ? '<p class="field-error" id="' . e($field) . '-error">' . icon('alert') . ' ' . e($errors[$field]) . '</p>'
        : '';
}

/** aria attributes that tie an input to its error message. */
function invalid_attrs(array $errors, string $field): string
{
    return isset($errors[$field]) ? ' aria-invalid="true" aria-describedby="' . e($field) . '-error"' : '';
}

/** Hidden CSRF field for every state-changing form. */
function csrf_field(App\App $app): string
{
    return '<input type="hidden" name="_csrf" value="' . e(App\Auth\Csrf::token($app->session())) . '">';
}
