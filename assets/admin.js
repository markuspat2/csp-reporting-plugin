/**
 * CSP Reporting Plugin Admin JavaScript
 */

(function($) {
    'use strict';
    
    var CSPAdmin = {
        
        init: function() {
            this.bindEvents();
            this.initTooltips();
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
            
            // Close modal on outside click
            $(window).on('click', this.handleModalOutsideClick);

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
                CSPAdmin.showAlert('Error: No file path specified', 'error');
                return;
            }
            
            $button.prop('disabled', true).text('Loading...');
            
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
                        $('#log-viewer-modal').data('current-file', filePath).show();
                    } else {
                        CSPAdmin.showAlert(response.data.message || csp_admin_ajax.strings.error_occurred, 'error');
                    }
                },
                error: function() {
                    CSPAdmin.showAlert(csp_admin_ajax.strings.error_occurred, 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text('View');
                }
            });
        },
        
        downloadLogFile: function(e) {
            e.preventDefault();
            
            var filePath = $(this).data('file') || $('#log-viewer-modal').data('current-file');
            
            if (!filePath) {
                CSPAdmin.showAlert('Error: No file path specified', 'error');
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
            $button.prop('disabled', true).text('Clearing...');
            
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
                    $button.prop('disabled', false).text('Clear All Logs');
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
            $button.prop('disabled', true).text('Sending...');

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
                error: function(xhr, status, error) {
                    CSPAdmin.showAlert('Failed to send test report: ' + error, 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text('Send Test Report');
                }
            });
        },
        
        closeModal: function(e) {
            e.preventDefault();
            $('#log-viewer-modal').hide();
        },
        
        handleModalOutsideClick: function(e) {
            if (e.target.id === 'log-viewer-modal') {
                $('#log-viewer-modal').hide();
            }
        },
        
        showAlert: function(message, type) {
            type = type || 'info';
            
            var $alert = $('<div class="csp-alert csp-alert-' + type + '">' + message + '</div>');
            
            $('.csp-admin-page').prepend($alert);
            
            setTimeout(function() {
                $alert.fadeOut(300, function() {
                    $(this).remove();
                });
            }, 5000);
        },
        
        initTooltips: function() {
            // Add tooltips to buttons and form elements
            $('[title]').each(function() {
                var $this = $(this);
                var title = $this.attr('title');
                $this.removeAttr('title').attr('data-tooltip', title);
            });
        },
        
        debounce: function(func, wait) {
            var timeout;
            return function executedFunction() {
                var later = function() {
                    clearTimeout(timeout);
                    func.apply(this, arguments);
                }.bind(this);
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        }
    };
    
    // Initialize when document is ready
    $(document).ready(function() {
        CSPAdmin.init();
    });
    
    // Expose to global scope for debugging
    window.CSPAdmin = CSPAdmin;
    
})(jQuery);

