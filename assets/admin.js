/**
 * CSP Reporting Plugin Admin JavaScript
 */

(function($) {
    'use strict';
    
    var CSPAdmin = {
        
        init: function() {
            this.bindEvents();
        },
        
        bindEvents: function() {
            // View log file
            $(document).on('click', '.view-log', this.viewLogFile);
            
            // Download log file
            $(document).on('click', '.download-log, #download-current-log', this.downloadLogFile);
            
            // Clear logs
            $(document).on('click', '#clear-logs', this.clearLogs);
            
            // Refresh statistics
            $(document).on('click', '#refresh-stats', this.refreshStats);
            
            // Send test report
            $(document).on('click', '#send-test-report', this.sendTestReport);
            
            // Close modal
            $(document).on('click', '.csp-modal-close', this.closeModal);
            
            // Close modal on outside click or Escape
            $(window).on('click', this.handleModalOutsideClick);
            $(document).on('keydown', function(e) {
                if (e.key === 'Escape') {
                    $('#log-viewer-modal').addClass('hidden');
                }
            });

            // Allow blocked source from the violations table
            $(document).on('click', '.csp-allow-source', this.allowSource);

            // Select all checkboxes on the By Source rollup
            $(document).on('change', '#csp-select-all-sources', function() {
                $('.csp-by-source-table input[name="sources[]"]').prop('checked', this.checked);
            });
        },

        allowSource: function(e) {
            e.preventDefault();

            var $link = $(this);
            var violationId = $link.data('id');

            $.ajax({
                url: csp_admin_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'csp_allow_source',
                    violation_id: violationId,
                    nonce: csp_admin_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        CSPAdmin.showAlert(response.data.message, 'success');
                    } else {
                        CSPAdmin.showAlert((response.data && response.data.message) || csp_admin_ajax.strings.error_occurred, 'error');
                    }
                },
                error: function() {
                    CSPAdmin.showAlert(csp_admin_ajax.strings.error_occurred, 'error');
                }
            });
        },
        
        viewLogFile: function(e) {
            e.preventDefault();
            
            var $button = $(this);
            var filePath = $button.data('file');
            
            if (!filePath) {
                CSPAdmin.showAlert(csp_admin_ajax.strings.no_file, 'error');
                return;
            }
            
            $button.prop('disabled', true).text(csp_admin_ajax.strings.loading);
            
            $.ajax({
                url: csp_admin_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'csp_get_log_content',
                    file_path: filePath,
                    nonce: csp_admin_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        $('#log-content').text(response.data.content);
                        $('#log-viewer-modal').data('current-file', filePath).removeClass('hidden');
                        $('#log-viewer-modal .csp-modal-close').first().trigger('focus');
                    } else {
                        CSPAdmin.showAlert(response.data.message || csp_admin_ajax.strings.error_occurred, 'error');
                    }
                },
                error: function() {
                    CSPAdmin.showAlert(csp_admin_ajax.strings.error_occurred, 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text(csp_admin_ajax.strings.view);
                }
            });
        },
        
        downloadLogFile: function(e) {
            e.preventDefault();
            
            var filePath = $(this).data('file') || $('#log-viewer-modal').data('current-file');
            
            if (!filePath) {
                CSPAdmin.showAlert(csp_admin_ajax.strings.no_file, 'error');
                return;
            }
            
            var form = $('<form>', {
                method: 'POST',
                action: csp_admin_ajax.ajax_url,
                target: '_blank'
            });
            
            form.append($('<input>', {
                type: 'hidden',
                name: 'action',
                value: 'csp_download_log'
            }));
            
            form.append($('<input>', {
                type: 'hidden',
                name: 'file_path',
                value: filePath
            }));
            
            form.append($('<input>', {
                type: 'hidden',
                name: 'nonce',
                value: csp_admin_ajax.nonce
            }));
            
            $('body').append(form);
            form.submit();
            form.remove();
        },
        
        clearLogs: function(e) {
            e.preventDefault();
            
            if (!confirm(csp_admin_ajax.strings.confirm_clear_logs)) {
                return;
            }
            
            var $button = $(this);
            $button.prop('disabled', true).text(csp_admin_ajax.strings.clearing);
            
            $.ajax({
                url: csp_admin_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'csp_clear_logs',
                    nonce: csp_admin_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        CSPAdmin.showAlert(response.data.message, 'success');
                        setTimeout(function() {
                            location.reload();
                        }, 1500);
                    } else {
                        CSPAdmin.showAlert(response.data.message || csp_admin_ajax.strings.error_occurred, 'error');
                    }
                },
                error: function() {
                    CSPAdmin.showAlert(csp_admin_ajax.strings.error_occurred, 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text(csp_admin_ajax.strings.clear_logs);
                }
            });
        },
        
        refreshStats: function(e) {
            e.preventDefault();
            location.reload();
        },
        
        sendTestReport: function(e) {
            e.preventDefault();
            
            var $button = $(this);
            $button.prop('disabled', true).text(csp_admin_ajax.strings.sending);

            $.ajax({
                url: csp_admin_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'csp_send_test_report',
                    nonce: csp_admin_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        CSPAdmin.showAlert(response.data.message, 'success');
                        setTimeout(function() {
                            location.reload();
                        }, 1500);
                    } else {
                        CSPAdmin.showAlert((response.data && response.data.message) || csp_admin_ajax.strings.error_occurred, 'error');
                    }
                },
                error: function() {
                    CSPAdmin.showAlert(csp_admin_ajax.strings.error_occurred, 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text(csp_admin_ajax.strings.send_test_report);
                }
            });
        },
        
        closeModal: function(e) {
            e.preventDefault();
            $('#log-viewer-modal').addClass('hidden');
        },
        
        handleModalOutsideClick: function(e) {
            if (e.target.id === 'log-viewer-modal') {
                $('#log-viewer-modal').addClass('hidden');
            }
        },
        
        // Standard admin notice (notice-success / notice-error / ...),
        // announced to screen readers. Messages can echo report data (e.g. a
        // blocked origin), so they are always inserted as text, never HTML.
        showAlert: function(message, type) {
            type = type || 'info';

            var $notice = $('<div>', { 'class': 'notice notice-' + type + ' is-dismissible' })
                .append($('<p>').text(message));
            var $anchor = $('.csp-admin-page .wp-header-end').first();

            $('.csp-admin-page .notice.csp-js-notice').remove();
            $notice.addClass('csp-js-notice');

            if ($anchor.length) {
                $anchor.after($notice);
            } else {
                $('.csp-admin-page').prepend($notice);
            }

            // Lets core's common.js add the dismiss button to the new notice.
            $(document).trigger('wp-updates-notice-added');

            if (window.wp && wp.a11y && wp.a11y.speak) {
                wp.a11y.speak(message, type === 'error' ? 'assertive' : 'polite');
            }
        }
    };
    
    // Initialize when document is ready
    $(document).ready(function() {
        CSPAdmin.init();
    });
    
    // Expose to global scope for debugging
    window.CSPAdmin = CSPAdmin;
    
})(jQuery);

