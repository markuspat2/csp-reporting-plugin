/**
 * CSP Reporting Plugin — Policy Builder
 *
 * Live header preview, service presets, and delivery-mode UI for the
 * per-directive policy editor on the settings screen.
 */

(function($) {
    'use strict';

    var PRESETS = {
        'google-fonts': {
            'style-src': ['https://fonts.googleapis.com'],
            'font-src': ['https://fonts.gstatic.com']
        },
        'google-analytics': {
            'script-src': ['https://www.googletagmanager.com', 'https://www.google-analytics.com'],
            'img-src': ['https://www.google-analytics.com'],
            'connect-src': ['https://www.google-analytics.com', 'https://analytics.google.com', 'https://www.googletagmanager.com']
        },
        'gtm': {
            'script-src': ['https://www.googletagmanager.com'],
            'img-src': ['https://www.googletagmanager.com'],
            'connect-src': ['https://www.googletagmanager.com']
        },
        'youtube': {
            'frame-src': ['https://www.youtube.com', 'https://www.youtube-nocookie.com'],
            'img-src': ['https://i.ytimg.com']
        }
    };

    function directiveInput(directive) {
        return $('.csp-directive-input[data-directive="' + directive + '"]');
    }

    function addSources(directive, sources) {
        var $input = directiveInput(directive);
        if (!$input.length) {
            return;
        }

        var current = $.trim($input.val());
        var list = current === '' ? [] : current.split(/\s+/);

        $.each(sources, function(_, source) {
            if ($.inArray(source, list) === -1) {
                list.push(source);
            }
        });

        $input.val(list.join(' ')).trigger('input');
    }

    function updatePreview() {
        var parts = [];

        $('#csp-policy-builder .csp-directive-input').each(function() {
            var directive = $(this).data('directive');
            var value = $.trim($(this).val()).replace(/\s+/g, ' ');
            if (value !== '') {
                parts.push(directive + ' ' + value);
            }
        });

        $('#csp-policy-builder input[type="checkbox"]:checked').each(function() {
            var name = $(this).attr('name') || '';
            var match = name.match(/\[([a-z-]+)\]$/);
            if (match) {
                parts.push(match[1]);
            }
        });

        var $preview = $('#csp-policy-preview');
        if ($preview.length) {
            $preview.text(parts.length ? parts.join('; ') + '; report-uri <endpoint>' : '');
        }
    }

    $(document).ready(function() {
        if (!$('#csp-policy-builder').length) {
            return;
        }

        $(document).on('input change', '#csp-policy-builder input', updatePreview);
        updatePreview();

        $(document).on('click', '.csp-preset', function(e) {
            e.preventDefault();
            var preset = PRESETS[$(this).data('preset')];
            if (!preset) {
                return;
            }
            $.each(preset, function(directive, sources) {
                addSources(directive, sources);
            });
        });

        $(document).on('change', '#csp-mode-select', function() {
            $('#csp-test-policy-row').toggle($(this).val() === 'both');
        });
    });

})(jQuery);
