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
            
            // Close modal
            $(document).on('click', '.csp-modal-close', this.closeModal);
            
            // Close modal on outside click
            $(window).on('click', this.handleModalOutsideClick);
            
            // CSP policy validation
            $(document).on('input', 'textarea[name="csp_reporting_options[csp_policy]"]', this.validateCSPPolicy);
            
            // Auto-save draft
            $(document).on('input', 'textarea[name="csp_reporting_options[csp_policy]"]', this.debounce(this.autoSaveDraft, 2000));
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
        
        closeModal: function(e) {
            e.preventDefault();
            $('#log-viewer-modal').hide();
        },
        
        handleModalOutsideClick: function(e) {
            if (e.target.id === 'log-viewer-modal') {
                $('#log-viewer-modal').hide();
            }
        },
        
        validateCSPPolicy: function(e) {
            var policy = $(this).val();
            var $textarea = $(this);
            
            // Remove previous validation classes
            $textarea.removeClass('csp-valid csp-invalid');
            
            if (!policy.trim()) {
                return;
            }
            
            // Basic CSP validation
            var directives = policy.split(';').map(function(d) { return d.trim(); });
            var validDirectives = [
                'default-src', 'script-src', 'style-src', 'img-src', 'font-src',
                'connect-src', 'frame-src', 'object-src', 'media-src', 'manifest-src',
                'worker-src', 'child-src', 'form-action', 'frame-ancestors', 'base-uri',
                'plugin-types', 'sandbox', 'upgrade-insecure-requests', 'block-all-mixed-content'
            ];
            
            var isValid = true;
            var invalidDirectives = [];
            
            directives.forEach(function(directive) {
                if (directive) {
                    var parts = directive.split(' ');
                    var directiveName = parts[0];
                    
                    if (validDirectives.indexOf(directiveName) === -1) {
                        isValid = false;
                        invalidDirectives.push(directiveName);
                    }
                }
            });
            
            if (isValid) {
                $textarea.addClass('csp-valid');
                CSPAdmin.hideValidationMessage($textarea);
            } else {
                $textarea.addClass('csp-invalid');
                CSPAdmin.showValidationMessage($textarea, 'Invalid directives: ' + invalidDirectives.join(', '));
            }
        },
        
        showValidationMessage: function($element, message) {
            $element.siblings('.csp-validation-message').remove();
            $element.after('<div class="csp-validation-message" style="color: #d63638; font-size: 12px; margin-top: 5px;">' + message + '</div>');
        },
        
        hideValidationMessage: function($element) {
            $element.siblings('.csp-validation-message').remove();
        },
        
        autoSaveDraft: function() {
            var policy = $('textarea[name="csp_reporting_options[csp_policy]"]').val();
            
            if (policy.trim()) {
                localStorage.setItem('csp_policy_draft', policy);
            } else {
                localStorage.removeItem('csp_policy_draft');
            }
        },
        
        loadDraft: function() {
            var draft = localStorage.getItem('csp_policy_draft');
            if (draft) {
                $('textarea[name="csp_reporting_options[csp_policy]"]').val(draft);
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
        CSPAdmin.loadDraft();
    });
    
    // Expose to global scope for debugging
    window.CSPAdmin = CSPAdmin;
    
})(jQuery);

