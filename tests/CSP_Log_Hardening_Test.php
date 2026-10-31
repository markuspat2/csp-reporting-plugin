<?php

use PHPUnit\Framework\TestCase;

/**
 * Raw log files must not be guessable or served by the web server.
 */
class CSP_Log_Hardening_Test extends TestCase {

    private $dir;

    protected function setUp(): void {
        $GLOBALS['csp_test_options'] = array();
        $this->dir                   = CSP_REPORTING_LOG_DIR;
        wp_mkdir_p($this->dir);
        foreach (array_merge((array) glob($this->dir . '*.log'), array( $this->dir . '.htaccess', $this->dir . 'index.php' )) as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
    }

    private function report() {
        return array( 'csp-report' => array( 'document-uri' => 'https://example.test/', 'violated-directive' => 'img-src' ) );
    }

    public function test_log_file_name_carries_a_random_secret() {
        $logger = new CSP_Logger();
        $logger->log_violation($this->report());

        $files = $logger->get_log_files();
        $this->assertCount(1, $files);

        $secret = get_option(CSP_Logger::SECRET_OPTION);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9]{24}$/', $secret);
        $this->assertSame('csp-reports-' . current_time('Y-m-d') . '-' . $secret . '.log', basename($files[0]));
    }

    public function test_protect_directory_writes_apache_22_and_24_rules() {
        file_put_contents($this->dir . '.htaccess', "Order Deny,Allow\nDeny from all\n"); // Pre-2.2.0 copy.

        ( new CSP_Logger() )->protect_directory();

        $htaccess = file_get_contents($this->dir . '.htaccess');
        $this->assertStringContainsString('Require all denied', $htaccess);
        $this->assertStringContainsString('Deny from all', $htaccess);
        $this->assertFileExists($this->dir . 'index.php');
    }

    public function test_harden_renames_only_predictable_names() {
        $legacy  = array( 'csp-reports-2025-01-02.log', 'csp-reports-2025-01-02-2025-01-02-10-11-12.log' );
        $foreign = 'csp-reports-2025-01-02-OTHERSITESECRETxxxxxxx.log';
        foreach (array_merge($legacy, array( $foreign )) as $name) {
            file_put_contents($this->dir . $name, "{}\n");
        }

        $logger  = new CSP_Logger();
        $renamed = $logger->harden_log_directory();
        $secret  = get_option(CSP_Logger::SECRET_OPTION);

        $this->assertSame(2, $renamed);
        foreach ($legacy as $name) {
            $this->assertFileDoesNotExist($this->dir . $name);
            $this->assertFileExists($this->dir . substr($name, 0, -4) . '-' . $secret . '.log');
        }
        $this->assertFileExists($this->dir . $foreign, "another site's secret-named file is left alone");
        $this->assertSame(0, $logger->harden_log_directory(), 'idempotent');
    }

    public function test_statistics_do_not_parse_file_contents() {
        file_put_contents($this->dir . 'csp-reports-2025-01-02-abcdefghijklmnopqrstuvwx.log', str_repeat("{}\n", 10));

        $stats = ( new CSP_Logger() )->get_log_statistics();

        $this->assertSame(1, $stats['total_files']);
        $this->assertSame(30, $stats['total_size']);
        $this->assertArrayNotHasKey('total_entries', $stats);
    }
}
