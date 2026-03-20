import { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { OAuthClientInformationFull, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import { Response } from 'express';
import logger from './logger.js';
import AuthManager from './auth.js';
import type { AppSecrets } from './secrets.js';
import { getCloudEndpoints } from './cloud-config.js';

// In-memory store for dynamically registered clients
const registeredClients = new Map<string, OAuthClientInformationFull>();

export class MicrosoftOAuthProvider extends ProxyOAuthServerProvider {
  private authManager: AuthManager;
  private azureClientId: string;
  private azureClientSecret: string;
  private msTokenUrl: string;

  constructor(authManager: AuthManager, secrets: AppSecrets) {
    const tenantId = secrets.tenantId || 'common';
    const clientId = secrets.clientId;
    const clientSecret = secrets.clientSecret;
    const cloudEndpoints = getCloudEndpoints(secrets.cloudType);
    const tokenUrl = `${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/token`;

    super({
      endpoints: {
        authorizationUrl: `${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/authorize`,
        tokenUrl,
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
        const stored = registeredClients.get(client_id);
        if (stored) {
          logger.info(`getClient: returning stored client for ${client_id}`);
          return stored;
        }
        logger.info(`getClient: no stored client for ${client_id}, returning defaults`);
        return {
          client_id,
          redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'],
        };
      },
    });

    this.authManager = authManager;
    this.azureClientId = clientId;
    this.azureClientSecret = clientSecret;
    this.msTokenUrl = tokenUrl;
  }

  // Override clientsStore to intercept dynamic registration and store client data
  get clientsStore(): OAuthRegisteredClientsStore {
    const parentStore = super.clientsStore;
    return {
      getClient: parentStore.getClient,
      registerClient: async (client: OAuthClientInformationFull): Promise<OAuthClientInformationFull> => {
        logger.info(`registerClient: storing client ${client.client_id} with redirect_uris: ${JSON.stringify(client.redirect_uris)}`);
        const registeredClient: OAuthClientInformationFull = {
          ...client,
          client_id: client.client_id || `mcp-client-${Date.now()}`,
          client_secret: `mcp-secret-${Date.now()}-${Math.random().toString(36).substring(2)}`,
          client_id_issued_at: Math.floor(Date.now() / 1000),
        };
        registeredClients.set(registeredClient.client_id, registeredClient);
        logger.info(`registerClient: stored client ${registeredClient.client_id} successfully`);
        return registeredClient;
      },
    };
  }

  // Override authorize to use Azure app client_id when redirecting to Microsoft
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    logger.info(`authorize: swapping MCP client_id ${client.client_id} with Azure client_id ${this.azureClientId}`);
    const azureClient = {
      ...client,
      client_id: this.azureClientId,
    };
    return super.authorize(azureClient, params, res);
  }

  // Override exchangeAuthorizationCode to use Azure app credentials with Microsoft token endpoint
  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    logger.info(`exchangeAuthorizationCode: using Azure client_id ${this.azureClientId} instead of MCP client ${client.client_id}`);

    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.azureClientId,
      code: authorizationCode,
      client_secret: this.azureClientSecret,
    });

    if (codeVerifier) params.set('code_verifier', codeVerifier);
    if (redirectUri) params.set('redirect_uri', redirectUri);
    if (resource) params.set('resource', resource.href);

    const response = await fetch(this.msTokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      logger.error(`Token exchange failed: ${response.status} - ${errorBody}`);
      throw new Error(`Token exchange failed: ${response.status}`);
    }

    const data = await response.json();
    logger.info('Token exchange successful');
    return {
      access_token: data.access_token,
      token_type: data.token_type || 'Bearer',
      expires_in: data.expires_in,
      refresh_token: data.refresh_token,
      scope: data.scope,
    };
  }

  // Override exchangeRefreshToken to use Azure app credentials
  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    logger.info(`exchangeRefreshToken: using Azure client_id ${this.azureClientId}`);

    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.azureClientId,
      refresh_token: refreshToken,
      client_secret: this.azureClientSecret,
    });

    if (scopes && scopes.length > 0) params.set('scope', scopes.join(' '));
    if (resource) params.set('resource', resource.href);

    const response = await fetch(this.msTokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      logger.error(`Refresh token exchange failed: ${response.status} - ${errorBody}`);
      throw new Error(`Refresh token exchange failed: ${response.status}`);
    }

    const data = await response.json();
    logger.info('Refresh token exchange successful');
    return {
      access_token: data.access_token,
      token_type: data.token_type || 'Bearer',
      expires_in: data.expires_in,
      refresh_token: data.refresh_token,
      scope: data.scope,
    };
  }
}
