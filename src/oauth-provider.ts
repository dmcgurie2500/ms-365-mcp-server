import { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import logger from './logger.js';
import AuthManager from './auth.js';
import type { AppSecrets } from './secrets.js';
import { getCloudEndpoints } from './cloud-config.js';

// In-memory store for dynamically registered clients
const registeredClients = new Map<string, OAuthClientInformationFull>();

export class MicrosoftOAuthProvider extends ProxyOAuthServerProvider {
  private authManager: AuthManager;

  constructor(authManager: AuthManager, secrets: AppSecrets) {
    const tenantId = secrets.tenantId || 'common';
    const clientId = secrets.clientId;
    const cloudEndpoints = getCloudEndpoints(secrets.cloudType);

    super({
      endpoints: {
        authorizationUrl: `${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/authorize`,
        tokenUrl: `${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/token`,
        revocationUrl: `${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/logout`,
      },
      verifyAccessToken: async (token: string): Promise<AuthInfo> => {
        try {
          const response = await fetch(`${cloudEndpoints.graphApi}/v1.0/me`, {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          });

          if (response.ok) {
            const userData = await response.json();
            logger.info(`OAuth token verified for user: ${userData.userPrincipalName}`);

            await authManager.setOAuthToken(token);

            return {
              token,
              clientId,
              scopes: [],
            };
          } else {
            throw new Error(`Token verification failed: ${response.status}`);
          }
        } catch (error) {
          logger.error(`OAuth token verification error: ${error}`);
          throw error;
        }
      },
      getClient: async (client_id: string) => {
        // Return stored registration data if available (includes exact redirect_uri with port)
        const stored = registeredClients.get(client_id);
        if (stored) {
          logger.info(`getClient: returning stored client data for ${client_id} with redirect_uris: ${JSON.stringify(stored.redirect_uris)}`);
          return stored;
        }
        // Fallback for non-dynamically-registered clients
        logger.info(`getClient: no stored client for ${client_id}, returning default redirect_uris`);
        return {
          client_id,
          redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'],
        };
      },
    });

    this.authManager = authManager;
  }

  // Override clientsStore to intercept dynamic registration and store client data
  get clientsStore(): OAuthRegisteredClientsStore {
    const parentStore = super.clientsStore;
    return {
      getClient: parentStore.getClient,
      registerClient: async (client: OAuthClientInformationFull): Promise<OAuthClientInformationFull> => {
        logger.info(`registerClient: storing client ${client.client_id} with redirect_uris: ${JSON.stringify(client.redirect_uris)}`);
        // Generate a client_secret for the registered client
        const registeredClient: OAuthClientInformationFull = {
          ...client,
          client_id: client.client_id || `mcp-client-${Date.now()}`,
          client_secret: `mcp-secret-${Date.now()}-${Math.random().toString(36).substring(2)}`,
          client_id_issued_at: Math.floor(Date.now() / 1000),
        };
        // Store the client data including the exact redirect_uris from registration
        registeredClients.set(registeredClient.client_id, registeredClient);
        logger.info(`registerClient: stored client ${registeredClient.client_id} successfully`);
        return registeredClient;
      },
    };
  }
}import { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import logger from './logger.js';
import AuthManager from './auth.js';
import type { AppSecrets } from './secrets.js';
import { getCloudEndpoints } from './cloud-config.js';

export class MicrosoftOAuthProvider extends ProxyOAuthServerProvider {
      private authManager: AuthManager;

  constructor(authManager: AuthManager, secrets: AppSecrets) {
          const tenantId = secrets.tenantId || 'common';
          const clientId = secrets.clientId;
          const cloudEndpoints = getCloudEndpoints(secrets.cloudType);

        super({
                  endpoints: {
                              authorizationUrl: `${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/authorize`,
                              tokenUrl: `${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/token`,
                              revocationUrl: `${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/logout`,
                  },
                  verifyAccessToken: async (token: string): Promise<AuthInfo> => {
                              try {
                                            const response = await fetch(`${cloudEndpoints.graphApi}/v1.0/me`, {
                                                            headers: {
                                                                              Authorization: `Bearer ${token}`,
                                                            },
                                            });

                                if (response.ok) {
                                                const userData = await response.json();
                                                logger.info(`OAuth token verified for user: ${userData.userPrincipalName}`);

                                              await authManager.setOAuthToken(token);

                                              return {
                                                                token,
                                                                clientId,
                                                                scopes: [],
                                              };
                                } else {
                                                throw new Error(`Token verification failed: ${response.status}`);
                                }
                              } catch (error) {
                                            logger.error(`OAuth token verification error: ${error}`);
                                            throw error;
                              }
                  },
                  getClient: async (client_id: string) => {
                              return {
                                            client_id,
                                            redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'],
                              };
                  },
        });

        this.authManager = authManager;
  }
}
