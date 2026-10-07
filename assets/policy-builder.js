/**
 * CSP Reporting Plugin — Policy Builder
 *
 * Live header preview (including nonce mode), service presets, and
 * delivery-mode UI for the per-directive policy editor on the settings
 * screen.
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
        },
        'recaptcha': {
            'script-src': ['https://www.google.com', 'https://www.gstatic.com'],
            'frame-src': ['https://www.google.com']
        },
        'jetpack': {
            'script-src': ['https://s0.wp.com', 'https://stats.wp.com'],
            'style-src': ['https://s0.wp.com'],
            'img-src': ['https://s0.wp.com', 'https://pixel.wp.com'],
            'frame-src': ['https://wordpress.com', 'https://widgets.wp.com'],
            'connect-src': ['https://stats.wp.com']
        },
        'userway': {
            'script-src': ['https://cdn.userway.org'],
            'style-src': ['https://cdn.userway.org'],
            'img-src': ['https://cdn.userway.org'],
            'connect-src': ['https://api.userway.org']
        },
        'userback': {
            'script-src': ['https://static.userback.io'],
            'style-src': ['https://static.userback.io'],
            'connect-src': ['https://api.userback.io']
        },
        'cloudflare-insights': {
            'script-src': ['https://static.cloudflareinsights.com'],
            'connect-src': ['https://cloudflareinsights.com']
        },
        'jsdelivr': {
            'script-src': ['https://cdn.jsdelivr.net'],
            'style-src': ['https://cdn.jsdelivr.net'],
            'font-src': ['https://cdn.jsdelivr.net']
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

    var NONCE_PLACEHOLDER = "'nonce-{generated per request}'";

    function isOn(id) {
        var $el = $('#' + id);
        return $el.length > 0 && $el.is(':checked') && !$el.is(':disabled');
    }

    // [[name, value], ...] from the builder, in display order.
    function builderDirectives() {
        var pairs = [];

        $('#csp-policy-builder .csp-directive-input').each(function() {
            var value = $.trim($(this).val()).replace(/\s+/g, ' ');
            if (value !== '') {
                pairs.push([$(this).data('directive'), value]);
            }
        });

        $('#csp-policy-builder input[type="checkbox"]:checked').each(function() {
            var match = ($(this).attr('name') || '').match(/\[([a-z-]+)\]$/);
            if (match) {
                pairs.push([match[1], '']);
            }
        });

        return pairs;
    }

    // Mirrors CSP_Policy::parse_policy_text() closely enough for a preview.
    function parsePolicy(text) {
        var pairs = [];

        $.each(String(text).split(';'), function(_, part) {
            part = $.trim(part.replace(/\s+/g, ' '));
            if (part === '') {
                return;
            }
            var space = part.indexOf(' ');
            var name = (space === -1 ? part : part.slice(0, space)).toLowerCase();
            if (name === 'report-uri' || name === 'report-to') {
                return;
            }
            pairs.push([name, space === -1 ? '' : $.trim(part.slice(space + 1))]);
        });

        return pairs;
    }

    function indexOf(pairs, name) {
        for (var i = 0; i < pairs.length; i++) {
            if (pairs[i][0] === name) {
                return i;
            }
        }
        return -1;
    }

    // Mirrors CSP_Policy::add_script_sources().
    function addScriptSources(pairs, nonceSources, sampleSources) {
        if (!nonceSources.length && !sampleSources.length) {
            return pairs;
        }

        pairs = $.map(pairs, function(pair) {
            return [[pair[0], pair[1]]];
        });

        if (indexOf(pairs, 'script-src') === -1) {
            var defaultIndex = indexOf(pairs, 'default-src');
            if (defaultIndex !== -1) {
                pairs.splice(defaultIndex + 1, 0, ['script-src', pairs[defaultIndex][1]]);
            } else if (nonceSources.length) {
                pairs.push(['script-src', '']);
            } else {
                return pairs;
            }
        }

        var targets = {
            'script-src': nonceSources.concat(sampleSources),
            'script-src-elem': nonceSources.concat(sampleSources),
            'script-src-attr': sampleSources
        };

        $.each(targets, function(name, additions) {
            var index = indexOf(pairs, name);
            if (index === -1 || !additions.length) {
                return;
            }
            var current = $.trim(pairs[index][1]);
            var sources = (current === '' || current.toLowerCase() === "'none'") ? [] : current.split(' ');
            var lower = $.map(sources, function(source) {
                return source.toLowerCase();
            });
            $.each(additions, function(_, source) {
                if ($.inArray(source.toLowerCase(), lower) === -1) {
                    sources.push(source);
                }
            });
            pairs[index][1] = sources.join(' ');
        });

        return pairs;
    }

    function headerValue(pairs, context) {
        var nonce = [];
        var samples = isOn('csp-report-sample') ? ["'report-sample'"] : [];

        if (isOn(context === 'enforce' ? 'csp-nonce-enforce' : 'csp-nonce-report-only')) {
            nonce.push(NONCE_PLACEHOLDER);
            if (isOn('csp-strict-dynamic')) {
                nonce.push("'strict-dynamic'");
            }
        }

        var parts = $.map(addScriptSources(pairs, nonce, samples), function(pair) {
            return pair[1] === '' ? pair[0] : pair[0] + ' ' + pair[1];
        });

        return parts.length ? parts.join('; ') + '; report-uri <endpoint>; report-to csp-endpoint' : '';
    }

    // Shows each header the current mode sends, as CSP_Policy::get_headers()
    // builds it.
    function updatePreview() {
        var $preview = $('#csp-policy-preview');
        if (!$preview.length) {
            return;
        }

        var mode = $('#csp-mode-select').val() || 'report-only';
        var main = builderDirectives();
        var lines = [];
        var value;

        if (mode === 'enforce' || mode === 'both') {
            value = headerValue(main, 'enforce');
            if (value) {
                lines.push('Content-Security-Policy: ' + value);
            }
        }

        if (mode === 'report-only' || mode === 'both') {
            var pairs = main;
            if (mode === 'both') {
                var test = parsePolicy($('#csp-test-policy').val() || '');
                if (test.length) {
                    pairs = test;
                }
            }
            value = headerValue(pairs, 'report-only');
            if (value) {
                lines.push('Content-Security-Policy-Report-Only: ' + value);
            }
        }

        $preview.text(lines.join('\n\n'));
    }

    $(document).ready(function() {
        if (!$('#csp-policy-builder').length) {
            return;
        }

        $(document).on(
            'input change',
            '#csp-policy-builder input, #csp-policy-builder textarea, #csp-mode-select, #csp-test-policy, .csp-nonce-option, #csp-report-sample',
            updatePreview
        );
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
