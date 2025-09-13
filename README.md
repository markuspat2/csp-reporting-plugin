# CSP Reporting Plugin

A WordPress plugin for Content Security Policy (CSP) report-only headers with server-side logging capabilities.

## Features

- **CSP Report-Only Headers**: Add Content Security Policy report-only headers to your WordPress site
- **Server-Side Logging**: Log CSP violation reports to files for analysis
- **Admin Interface**: User-friendly admin panel to manage CSP settings and view reports
- **Log Management**: View, download, and manage CSP violation logs
- **Statistics Dashboard**: View violation statistics and trends
- **Automatic Cleanup**: Automatic cleanup of old log files
- **Security**: Secure log file storage with proper access controls

## Installation

1. Upload the plugin files to `/wp-content/plugins/csp-reporting-plugin/`
2. Activate the plugin through the 'Plugins' screen in WordPress
3. Go to Settings > CSP Reporting to configure the plugin

## Configuration

### General Settings

- **Enable CSP Reporting**: Toggle CSP report-only headers on/off
- **CSP Policy**: Define your Content Security Policy directives

### Logging Settings

- **Log Retention (Days)**: How long to keep log files (default: 30 days)
- **Max Log File Size**: Maximum size of individual log files (default: 10MB)
- **Enable Admin Notices**: Show admin notifications for important events

## Default CSP Policy

The plugin comes with a sensible default CSP policy:

```
default-src 'self'; 
script-src 'self' 'unsafe-inline' 'unsafe-eval'; 
style-src 'self' 'unsafe-inline'; 
img-src 'self' data: https:; 
font-src 'self' data:; 
connect-src 'self'; 
frame-src 'none'; 
object-src 'none'; 
base-uri 'self'; 
form-action 'self';
```

## CSP Report Endpoint

The plugin creates a custom endpoint at `/csp-report-endpoint/` to receive violation reports. This endpoint:

- Accepts POST requests with CSP violation data
- Validates report structure
- Logs violations with metadata
- Returns appropriate HTTP status codes

## Log Files

CSP violation reports are logged to `/wp-content/csp-reports/` with the following features:

- Daily log file rotation
- Automatic file size rotation
- Secure file storage (protected by .htaccess)
- JSON format for easy parsing
- Rich metadata including IP, user agent, and WordPress context

## Admin Interface

The admin interface provides:

- **Settings Page**: Configure CSP policy and logging options
- **Log Viewer**: View log files directly in the browser
- **Statistics**: View violation counts and trends
- **File Management**: Download and clear log files
- **Quick Actions**: Test endpoint and refresh statistics

## Security Features

- Nonce verification for all AJAX requests
- Capability checks for admin functions
- Secure file path validation
- Protected log directory
- Input sanitization and validation

## Hooks and Filters

The plugin provides several hooks for customization:

### Actions

- `csp_cleanup_logs`: Daily cleanup of old log files
- `csp_violation_logged`: Fired when a violation is logged

### Filters

- `csp_report_data`: Modify violation report data before logging
- `csp_policy_directives`: Modify CSP policy before output

## Requirements

- WordPress 5.0 or higher
- PHP 7.4 or higher
- Write permissions to wp-content directory

## Changelog

### Version 1.0.0
- Initial release
- CSP report-only headers
- Server-side logging
- Admin interface
- Log management
- Statistics dashboard

## Support

For support and feature requests, please visit the plugin's support page.

## License

This plugin is licensed under the GPL v2 or later.

