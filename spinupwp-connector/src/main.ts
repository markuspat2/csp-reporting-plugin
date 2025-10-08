import type { Local } from './types/local-types';

export default function main(context: Local) {
  const logger = context.Logger.child({ namespace: 'spinupwp-connector:main' });
  logger.info('SpinupWP Connector main started');

  // Example: register a menu item under Site menu to open renderer panel
  try {
    context.hooks.addFilter(
      'siteInfoTools',
      'spinupwp-connector',
      (items: any[], site: any) => {
        return [
          ...items,
          {
            label: 'SpinupWP',
            name: 'spinupwp-connector-tools',
            onClick: () => {
              context.sendIPCEvent('spinupwp:open', { siteId: site?.id });
            },
          },
        ];
      }
    );
  } catch (error) {
    logger.error('Failed to register hooks', { error });
  }
}

