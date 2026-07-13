<?php
/**
 * CSP Notifications Class
 *
 * Email digests, immediate high-severity alerts, and Slack-compatible
 * webhook delivery.
 */

if ( ! defined('ABSPATH')) {
    exit;
}

class CSP_Notifications {

    /**
     * Maximum immediate high-severity alert emails per day.
     */
    const MAX_ALERTS_PER_DAY = 5;

    const DIGEST_HOOK = 'csp_send_digest';

    /**
     * @var CSP_Database
     */
    private $database;

    /**
     * Constructor
     *
     * @param CSP_Database $database
     */
    public function __construct( $database ) {
        $this->database = $database;

        add_action(self::DIGEST_HOOK, array( $this, 'send_digest' ));
        add_action('csp_violation_logged', array( $this, 'maybe_send_immediate_alert' ), 10, 2);
    }

    /**
     * Schedule the daily digest event (weekly frequency is handled inside
     * the handler so a settings change needs no rescheduling).
     */
    public static function schedule() {
        if ( ! wp_next_scheduled(self::DIGEST_HOOK)) {
            wp_schedule_event(time(), 'daily', self::DIGEST_HOOK);
        }
    }

    public static function unschedule() {
        wp_clear_scheduled_hook(self::DIGEST_HOOK);
    }

    /**
     * Get notification settings with defaults.
     *
     * @return array
     */
    private function get_settings() {
        $options = get_option('csp_reporting_options', array());

        return array(
            'email_enabled' => ! empty($options['notify_email_enabled']),
            'recipients' => ! empty($options['notify_email_recipients'])
                ? array_filter(array_map('trim', explode(',', $options['notify_email_recipients'])))
                : array( get_option('admin_email') ),
            'frequency' => isset($options['notify_digest_frequency']) && $options['notify_digest_frequency'] === 'weekly' ? 'weekly' : 'daily',
            'immediate_high' => ! empty($options['notify_immediate_high']),
            'webhook_url' => ! empty($options['notify_webhook_url']) ? $options['notify_webhook_url'] : '',
        );
    }

    /**
     * Send the scheduled digest (daily cron; weekly setting sends only on
     * Mondays).
     */
    public function send_digest() {
        $settings = $this->get_settings();

        if ( ! $settings['email_enabled'] && $settings['webhook_url'] === '') {
            return;
        }

        $days = 1;
        if ($settings['frequency'] === 'weekly') {
            if ( (int) current_time('N') !== 1) {
                return;
            }
            $days = 7;
        }

        $stats = $this->database->get_stats($days);

        if ($stats['total_hits'] < 1) {
            return;
        }

        $period = $settings['frequency'] === 'weekly'
            ? __('last 7 days', 'csp-reporting')
            : __('last 24 hours', 'csp-reporting');

        $subject = sprintf(
            /* translators: 1: site name, 2: report count, 3: period */
            __('[%1$s] CSP digest: %2$d violation reports in the %3$s', 'csp-reporting'),
            wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES),
            $stats['total_hits'],
            $period
        );

        $lines = array(
            sprintf(__('CSP violation digest for %s', 'csp-reporting'), home_url('/')),
            '',
            sprintf(__('Total reports: %d', 'csp-reporting'), $stats['total_hits']),
            sprintf(__('Unique violation patterns: %d', 'csp-reporting'), $stats['unique_patterns']),
            sprintf(
                __('Severity: %1$d high / %2$d medium / %3$d low', 'csp-reporting'),
                $stats['by_severity']['high'],
                $stats['by_severity']['medium'],
                $stats['by_severity']['low']
            ),
            '',
        );

        if ( ! empty($stats['top_blocked'])) {
            $lines[] = __('Top blocked sources:', 'csp-reporting');
            foreach ($stats['top_blocked'] as $row) {
                $lines[] = sprintf(
                    ' - %1$s (%2$s): %3$d',
                    $row['blocked_uri'] !== '' ? $row['blocked_uri'] : __('(inline)', 'csp-reporting'),
                    $row['directive'],
                    $row['hits']
                );
            }
            $lines[] = '';
        }

        $lines[] = sprintf(
            __('Review and tune the policy: %s', 'csp-reporting'),
            admin_url('options-general.php?page=csp-reporting&tab=violations')
        );

        $body = implode("\n", $lines);

        if ($settings['email_enabled'] && ! empty($settings['recipients'])) {
            wp_mail($settings['recipients'], $subject, $body);
        }

        $this->send_webhook($settings['webhook_url'], $subject . "\n\n" . $body);
    }

    /**
     * Send an immediate alert for a high-severity violation, throttled to
     * MAX_ALERTS_PER_DAY per day.
     *
     * Runs on csp_violation_logged.
     *
     * @param array $report
     * @param string $severity
     */
    public function maybe_send_immediate_alert( $report, $severity ) {
        if ($severity !== 'high') {
            return;
        }

        $settings = $this->get_settings();

        if ( ! $settings['immediate_high']) {
            return;
        }

        $count = (int) get_transient('csp_alerts_sent_today');

        /**
         * Filter the maximum immediate alerts per day.
         *
         * @param int $max
         */
        $max = apply_filters('csp_reporting_max_alerts_per_day', self::MAX_ALERTS_PER_DAY);

        if ($count >= $max) {
            return;
        }

        set_transient('csp_alerts_sent_today', $count + 1, DAY_IN_SECONDS);

        $csp_report = $report['csp-report'];

        $subject = sprintf(
            /* translators: %s: site name */
            __('[%s] High-severity CSP violation detected', 'csp-reporting'),
            wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES)
        );

        $body = implode("\n", array(
            sprintf(__('Page: %s', 'csp-reporting'), $csp_report['document-uri']),
            sprintf(__('Directive: %s', 'csp-reporting'), $csp_report['violated-directive']),
            sprintf(__('Blocked URI: %s', 'csp-reporting'), isset($csp_report['blocked-uri']) ? $csp_report['blocked-uri'] : ''),
            '',
            sprintf(__('Details: %s', 'csp-reporting'), admin_url('options-general.php?page=csp-reporting&tab=violations')),
        ));

        if ($settings['email_enabled'] && ! empty($settings['recipients'])) {
            wp_mail($settings['recipients'], $subject, $body);
        }

        $this->send_webhook($settings['webhook_url'], $subject . "\n\n" . $body);
    }

    /**
     * POST a Slack-compatible payload to the configured webhook.
     *
     * @param string $url
     * @param string $text
     */
    private function send_webhook( $url, $text ) {
        if ($url === '') {
            return;
        }

        wp_remote_post($url, array(
            'timeout' => 5,
            'headers' => array( 'Content-Type' => 'application/json' ),
            'body' => wp_json_encode(array( 'text' => $text )),
        ));
    }
}
