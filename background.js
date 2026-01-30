console.log('PIMfox for Entra loaded');

// Cache for roles data to enable instant popup display
let cachedRolesData = null;
let cachedRolesTimestamp = null;
const CACHE_VALIDITY_MS = 30000; // 30 seconds

/**
 * Token Decoder Module
 * Decodes JWT tokens and extracts user information
 */

// Function to decode JWT token without external libraries
function decodeToken(token) {
  if (!token) {
    return null;
  }

  try {
    // JWT tokens are made of three parts: header.payload.signature
    const parts = token.split('.');
    if (parts.length !== 3) {
      console.error('Invalid token format');
      return null;
    }

    // Decode the payload (middle part)
    const payload = parts[1];
    // Base64Url decode and parse as JSON
    const decoded = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    return decoded;
  } catch (error) {
    console.error('Error decoding token:', error);
    return null;
  }
}

// Function to extract principalId (oid) from token
function extractPrincipalId(token) {
  const decoded = decodeToken(token);
  if (!decoded) {
    return null;
  }
  
  // In Microsoft identity tokens, the 'oid' claim contains the user's Object ID
  return decoded.oid || null;
}

// Function to get user information from token
function getUserInfo(token) {
  const decoded = decodeToken(token);
  if (!decoded) {
    return null;
  }
  
  // Return common user properties from the token
  return {
    principalId: decoded.oid || null,
    upn: decoded.upn || decoded.email || null,
    name: decoded.name || null,
    preferredUsername: decoded.preferred_username || null
  };
}

/**
 * Token Encryption Module
 * Encrypts sensitive tokens before storing in local storage
 */

// Derive encryption key from extension runtime ID (stable across sessions)
let encryptionKey = null;

async function getEncryptionKey() {
  if (encryptionKey) {
    return encryptionKey;
  }

  // Use extension ID as key material (stable and unique per installation)
  const keyMaterial = browser.runtime.id || 'pimfox-default-key-material';
  const encoder = new TextEncoder();
  const keyData = encoder.encode(keyMaterial.padEnd(32, '0').substring(0, 32));

  // Import raw key material
  const importedKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  encryptionKey = importedKey;
  return encryptionKey;
}

// Encrypt a token string
async function encryptToken(token) {
  if (!token) return null;

  try {
    const key = await getEncryptionKey();
    const encoder = new TextEncoder();
    const data = encoder.encode(token);

    // Generate a random initialization vector
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Encrypt the token
    const encryptedData = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      data
    );

    // Combine IV and encrypted data for storage
    const combined = new Uint8Array(iv.length + encryptedData.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encryptedData), iv.length);

    // Convert to base64 for storage
    return btoa(String.fromCharCode(...combined));
  } catch (error) {
    console.error('Token encryption failed:', error);
    return token; // Fallback to unencrypted if encryption fails
  }
}

// Decrypt a token string
async function decryptToken(encryptedToken) {
  if (!encryptedToken) return null;

  try {
    const key = await getEncryptionKey();

    // Convert from base64
    const combined = Uint8Array.from(atob(encryptedToken), c => c.charCodeAt(0));

    // Extract IV and encrypted data
    const iv = combined.slice(0, 12);
    const encryptedData = combined.slice(12);

    // Decrypt the token
    const decryptedData = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      encryptedData
    );

    // Convert back to string
    const decoder = new TextDecoder();
    const decryptedToken = decoder.decode(decryptedData);
    
    // Validate it looks like a JWT token
    if (decryptedToken && decryptedToken.split('.').length === 3) {
      return decryptedToken;
    }
    
    console.error('Decrypted token is not a valid JWT format');
    return null;
  } catch (error) {
    console.error('Token decryption failed:', error);
    // Try to check if it's already an unencrypted JWT token (for backward compatibility)
    if (encryptedToken && typeof encryptedToken === 'string' && encryptedToken.split('.').length === 3) {
      console.log('Token appears to be unencrypted JWT, using as-is');
      return encryptedToken;
    }
    return null;
  }
}

// Listen for web requests to Microsoft Graph API
browser.webRequest.onBeforeRequest.addListener(
  function(details) {
    // Skip extension's own requests
    if (details.tabId === -1) {
      return;
    }
    
    if (details.url.includes('graph.microsoft.com')) {
      // We found a request to Graph API from a portal page
      captureAuthToken(details.requestId, details.url);
    }
  },
  {urls: ["https://graph.microsoft.com/*"]}
);

// Listen for web requests to Azure Management API
browser.webRequest.onBeforeRequest.addListener(
  function(details) {
    // Skip extension's own requests
    if (details.tabId === -1) {
      return;
    }
    
    if (details.url.includes('management.azure.com')) {
      // We found a request to Management API from a portal page
      captureAuthToken(details.requestId, details.url);
    }
  },
  {urls: ["https://management.azure.com/*"]}
);

// Capture authentication token from request headers
browser.webRequest.onSendHeaders.addListener(
  function(details) {
    // Skip requests made by the extension itself (tabId -1 means extension request)
    if (details.tabId === -1) {
      return;
    }
    
    // Only capture tokens from portal pages, not our own fetch() calls
    if (details.url.includes('graph.microsoft.com')) {
      const authHeader = details.requestHeaders.find(header =>
        header.name.toLowerCase() === 'authorization'
      );

      if (authHeader && authHeader.value.startsWith('Bearer ')) {
        // Extract the token (remove "Bearer " prefix)
        const token = authHeader.value.substring(7);

        // Encrypt and store the token
        encryptToken(token).then(encryptedToken => {
          browser.storage.local.set({
            graphToken: encryptedToken,
            tokenTimestamp: Date.now(),
            tokenSource: details.url
          });
          console.log('Graph API token captured and encrypted from portal!');
          
          // Pre-fetch role definitions AND roles data to cache them for popup
          // This prevents blocking popup rendering later
          setTimeout(() => {
            decryptToken(encryptedToken).then(decryptedToken => {
              if (decryptedToken) {
                // Fetch role definitions
                getRoleDefinitions(decryptedToken).catch(err => {
                  console.log('Background role definitions pre-fetch failed (non-critical):', err);
                });
                
                // Fetch and cache all roles data for instant popup display
                getAllRoles().then(rolesData => {
                  cachedRolesData = rolesData;
                  cachedRolesTimestamp = Date.now();
                  console.log('Roles data pre-cached for instant popup display');
                }).catch(err => {
                  console.log('Background roles pre-fetch failed (non-critical):', err);
                });
              }
            }).catch(err => {
              console.log('Token decryption for pre-fetch failed:', err);
            });
          }, 100); // Small delay to not block token storage
        }).catch(error => {
          console.error('Failed to encrypt Graph token:', error);
        });
      }
    }
  },
  {urls: ["https://graph.microsoft.com/*"]},
  ["requestHeaders"]
);

// Capture Azure Management API token from request headers
browser.webRequest.onSendHeaders.addListener(
  function(details) {
    // Skip requests made by the extension itself
    if (details.tabId === -1) {
      return;
    }
    
    if (details.url.includes('management.azure.com')) {
      const authHeader = details.requestHeaders.find(header =>
        header.name.toLowerCase() === 'authorization'
      );

      if (authHeader && authHeader.value.startsWith('Bearer ')) {
        // Extract the token (remove "Bearer " prefix)
        const token = authHeader.value.substring(7);

        // Encrypt and store the Azure Management token separately
        encryptToken(token).then(encryptedToken => {
          browser.storage.local.set({
            azureManagementToken: encryptedToken,
            azureManagementTokenTimestamp: Date.now(),
            azureManagementTokenSource: details.url
          });
          console.log('Azure Management API token captured and encrypted from portal!');
        }).catch(error => {
          console.error('Failed to encrypt Azure Management token:', error);
        });
      }
    }
  },
  {urls: ["https://management.azure.com/*"]},
  ["requestHeaders"]
);

// Function to capture auth token from a specific request
function captureAuthToken(requestId, url) {
  console.log(`Monitoring request to: ${url}`);
}

// Handle messages from popup
browser.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === "getPimRoles") {
    getPimRoles()
      .then(data => sendResponse({ success: true, data: data }))
      .catch(error => sendResponse({ success: false, error: error.toString() }));
    return true; // Indicates async response
  } else if (request.action === "getAzureResourceRoles") {
    getAzureResourceRoles()
      .then(data => sendResponse({ success: true, data: data }))
      .catch(error => sendResponse({ success: false, error: error.toString() }));
    return true;
  } else if (request.action === "getAllRoles") {
    console.log('[BACKGROUND] getAllRoles message received');
    getAllRoles()
      .then(data => {
        console.log('[BACKGROUND] Sending getAllRoles response');
        // Update cache when we fetch roles
        cachedRolesData = data;
        cachedRolesTimestamp = Date.now();
        sendResponse({ success: true, data: data });
      })
      .catch(error => {
        console.error('[BACKGROUND] getAllRoles error:', error);
        sendResponse({ success: false, error: error.toString() });
      });
    return true;
  } else if (request.action === "getCachedRoles") {
    // Return cached roles instantly without async operation
    console.log('[BACKGROUND] getCachedRoles message received');
    if (cachedRolesData && cachedRolesTimestamp) {
      const age = Date.now() - cachedRolesTimestamp;
      const isValid = age < CACHE_VALIDITY_MS;
      console.log(`[BACKGROUND] Returning cached roles (age: ${age}ms, valid: ${isValid})`);
      sendResponse({ 
        success: true, 
        data: cachedRolesData, 
        cached: true,
        cacheAge: age,
        cacheValid: isValid
      });
    } else {
      console.log('[BACKGROUND] No cached roles available');
      sendResponse({ success: false, error: 'No cached data available', cached: false });
    }
    return false; // Synchronous response
  } else if (request.action === "getActiveRoles") {
    getActiveRoles()
      .then(data => sendResponse({ success: true, data: data }))
      .catch(error => sendResponse({ success: false, error: error.toString() }));
    return true;
  } else if (request.action === "getTokenStatus") {
    console.log('[BACKGROUND] getTokenStatus message received');
    // Respond quickly to avoid blocking popup
    Promise.race([
      getTokenStatus(),
      new Promise((resolve) => setTimeout(() => {
        console.log('[BACKGROUND] getTokenStatus timeout, returning hasToken: false');
        resolve({ hasToken: false, timeout: true });
      }, 500))
    ])
      .then(status => {
        console.log('[BACKGROUND] Sending tokenStatus response:', status);
        sendResponse({ success: true, status: status });
      })
      .catch(error => {
        console.error('[BACKGROUND] getTokenStatus error:', error);
        sendResponse({ success: false, error: error.toString() });
      });
    return true;
  } else if (request.action === "manualSetToken") {
    setManualToken(request.token)
      .then(() => sendResponse({ success: true }))
      .catch(error => sendResponse({ success: false, error: error.toString() }));
    return true;
  } else if (request.action === "clearToken") {
    clearToken()
      .then(() => sendResponse({ success: true }))
      .catch(error => sendResponse({ success: false, error: error.toString() }));
    return true;
  } else if (request.action === "decryptToken") {
    decryptToken(request.encryptedToken)
      .then(token => sendResponse({ success: true, token: token }))
      .catch(error => sendResponse({ success: false, error: error.toString() }));
    return true;
  } else if (request.action === "getTokens") {
    // Get both tokens for role activation/deactivation
    browser.storage.local.get(['graphToken', 'azureManagementToken'])
      .then(async (result) => {
        const tokens = {};
        
        if (result.graphToken) {
          tokens.graphToken = await decryptToken(result.graphToken);
        }
        
        if (result.azureManagementToken) {
          tokens.azureManagementToken = await decryptToken(result.azureManagementToken);
        }
        
        sendResponse({ success: true, tokens: tokens });
      })
      .catch(error => sendResponse({ success: false, error: error.toString() }));
    return true;
  }
});

// Function to get PIM roles using the stored token
async function getPimRoles() {
  try {
    // Get token from storage
    const { graphToken: encryptedToken, tokenTimestamp } = 
      await browser.storage.local.get(['graphToken', 'tokenTimestamp']);
    
    if (!encryptedToken) {
      throw new Error('No Microsoft Graph token found. Please visit a Microsoft service like portal.azure.com first.');
    }
    
    // Decrypt the token
    const graphToken = await decryptToken(encryptedToken);
    
    if (!graphToken) {
      throw new Error('Failed to decrypt token. Please clear tokens and re-authenticate.');
    }
    
    // Check if token is older than 45 minutes (tokens typically expire after 1 hour)
    if (!tokenTimestamp) {
      throw new Error('Token timestamp missing. Please re-authenticate.');
    }
    const tokenAgeInMinutes = (Date.now() - tokenTimestamp) / (1000 * 60);
    if (tokenAgeInMinutes > 45) {
      throw new Error('Token may have expired. Please refresh your Microsoft service session.');
    }
    
    console.log('Using captured token to fetch PIM roles');
    
    // Extract principalId from token using the decoder function
    const principalId = extractPrincipalId(graphToken);
    
    if (!principalId) {
      throw new Error('Could not extract user ID from token. Please refresh your session.');
    }
    
    console.log('Using principalId:', principalId);
    
    // Call the PIM roles endpoint with the extracted principalId
    const response = await fetch(
      `https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules?$filter=principalId eq '${principalId}'`, 
      {
        method: "GET",
        headers: {
          'Authorization': `Bearer ${graphToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    if (!response.ok) {
      throw new Error(`API call failed: ${response.status} ${response.statusText}`);
    }
    
    const data = await response.json();
    
    // Resolve role definition names (non-blocking)
    // Only use cache to avoid blocking popup rendering with fetch
    if (data.value && data.value.length > 0) {
      const roleDefinitions = getRoleDefinitionsFromCacheOnly();
      
      if (roleDefinitions && Object.keys(roleDefinitions).length > 0) {
        // Map role definition IDs to friendly names
        data.value = data.value.map(role => {
          if (role.roleDefinitionId && roleDefinitions[role.roleDefinitionId]) {
            role.roleName = roleDefinitions[role.roleDefinitionId];
          }
          return role;
        });
      }
      // If no cache, roles will just use IDs (pre-fetch will populate for next time)
    }
    
    return data;
  } catch (error) {
    console.error('Error getting PIM roles:', error);
    throw error;
  }
}

// Cache for role definitions
let roleDefinitionsCache = null;
let roleDefinitionsCacheTime = null;

// Get role definitions from cache only (no fetch) to avoid blocking popup
function getRoleDefinitionsFromCacheOnly() {
  if (roleDefinitionsCache && roleDefinitionsCacheTime && 
      (Date.now() - roleDefinitionsCacheTime) < 3600000) {
    console.log('Using cached role definitions (cache-only mode)');
    return roleDefinitionsCache;
  }
  console.log('No cached role definitions available');
  return null;
}

// Function to get role definitions
async function getRoleDefinitions(token) {
  // Check if we have a recent cache (less than 1 hour old)
  if (roleDefinitionsCache && roleDefinitionsCacheTime && 
      (Date.now() - roleDefinitionsCacheTime) < 3600000) {
    console.log('Using cached role definitions');
    return roleDefinitionsCache;
  }
  
  console.log('Fetching role definitions from Graph API');
  try {
    // Set a timeout for the fetch to prevent blocking
    const fetchPromise = fetch(
      'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions', 
      {
        method: "GET",
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    // Race the fetch with a timeout
    const response = await Promise.race([
      fetchPromise,
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Role definitions fetch timeout')), 3000)
      )
    ]);
    
    if (!response.ok) {
      throw new Error(`Role definitions API call failed: ${response.status} ${response.statusText}`);
    }
    
    const data = await response.json();
    
    // Create a mapping of role definition ID to display name
    const roleDefinitions = {};
    if (data.value) {
      data.value.forEach(role => {
        if (role.id && role.displayName) {
          roleDefinitions[role.id] = role.displayName;
        }
      });
    }
    
    // Update the cache
    roleDefinitionsCache = roleDefinitions;
    roleDefinitionsCacheTime = Date.now();
    
    return roleDefinitions;
  } catch (error) {
    console.error('Error fetching role definitions:', error);
    return {}; // Return empty object on error
  }
}

// Function to get token status
async function getTokenStatus() {
  const { graphToken: encryptedToken, tokenTimestamp, tokenSource } = 
    await browser.storage.local.get(['graphToken', 'tokenTimestamp', 'tokenSource']);
  
  if (!encryptedToken) {
    return { hasToken: false };
  }
  
  // Decrypt token to verify it exists
  const graphToken = await decryptToken(encryptedToken);
  
  if (!graphToken || !tokenTimestamp) {
    return { hasToken: false };
  }
  
  const tokenAgeInMinutes = (Date.now() - tokenTimestamp) / (1000 * 60);
  
  return {
    hasToken: true,
    tokenAge: Math.round(tokenAgeInMinutes),
    isExpired: tokenAgeInMinutes > 45,
    source: tokenSource
  };
}

// Function to set a token manually
async function setManualToken(token) {
  if (!token || token.length < 50) {
    throw new Error('Invalid token provided');
  }
  
  // Encrypt token before storage
  const encryptedToken = await encryptToken(token);
  
  await browser.storage.local.set({
    graphToken: encryptedToken,
    tokenTimestamp: Date.now(),
    tokenSource: 'manual-entry'
  });
  
  return true;
}

// Function to clear the stored token
async function clearToken() {
  await browser.storage.local.remove(['graphToken', 'tokenTimestamp', 'tokenSource', 'azureManagementToken', 'azureManagementTokenTimestamp', 'azureManagementTokenSource']);
  return true;
}

// Function to get Azure resource PIM roles using the Azure Management token
async function getAzureResourceRoles() {
  try {
    // Get token from storage
    const { azureManagementToken: encryptedToken, azureManagementTokenTimestamp } =
      await browser.storage.local.get(['azureManagementToken', 'azureManagementTokenTimestamp']);

    if (!encryptedToken) {
      throw new Error('No Azure Management token found. Please visit Azure Portal first.');
    }
    
    // Decrypt the token
    const azureManagementToken = await decryptToken(encryptedToken);
    
    if (!azureManagementToken) {
      throw new Error('Failed to decrypt Azure Management token. Please clear tokens and re-authenticate.');
    }

    // Check if token is older than 45 minutes
    if (!azureManagementTokenTimestamp) {
      throw new Error('Token timestamp missing. Please re-authenticate.');
    }
    const tokenAgeInMinutes = (Date.now() - azureManagementTokenTimestamp) / (1000 * 60);
    if (tokenAgeInMinutes > 45) {
      throw new Error('Token may have expired. Please refresh your Azure Portal session.');
    }

    console.log('Using captured token to fetch Azure resource PIM roles');

    // Extract principalId from token
    const principalId = extractPrincipalId(azureManagementToken);

    if (!principalId) {
      throw new Error('Could not extract user ID from token. Please refresh your session.');
    }

    console.log('Using principalId:', principalId);

    // First, get all subscriptions the user has access to
    const subscriptionsResponse = await fetch(
      'https://management.azure.com/subscriptions?api-version=2020-01-01',
      {
        method: "GET",
        headers: {
          'Authorization': `Bearer ${azureManagementToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (!subscriptionsResponse.ok) {
      if (subscriptionsResponse.status === 401) {
        throw new Error('Azure Management token expired or invalid. Please visit Azure Portal (portal.azure.com), navigate around to refresh your session, then click Refresh in this extension.');
      }
      throw new Error(`Subscriptions API call failed: ${subscriptionsResponse.status} ${subscriptionsResponse.statusText}`);
    }

    const subscriptionsData = await subscriptionsResponse.json();

    if (!subscriptionsData.value || subscriptionsData.value.length === 0) {
      return { value: [] }; // No subscriptions found
    }

    // Fetch role eligibility for each subscription
    const allRoles = [];

    for (const subscription of subscriptionsData.value) {
      // Validate subscription object
      if (!subscription || !subscription.subscriptionId) {
        console.warn('Skipping invalid subscription object:', subscription);
        continue;
      }
      
      try {
        const response = await fetch(
          `https://management.azure.com/subscriptions/${subscription.subscriptionId}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=asTarget()`,
          {
            method: "GET",
            headers: {
              'Authorization': `Bearer ${azureManagementToken}`,
              'Content-Type': 'application/json'
            }
          }
        );

        if (response.ok) {
          const data = await response.json();

          if (data.value && data.value.length > 0) {
            // Add subscription context to each role
            data.value.forEach(role => {
              role.subscriptionId = subscription.subscriptionId;
              role.subscriptionName = subscription.displayName;
              role.roleType = 'azureResource'; // Mark as Azure resource role
            });

            allRoles.push(...data.value);
          }
        } else {
          console.warn(`Failed to fetch roles for subscription ${subscription.subscriptionId}: ${response.status}`);
        }
      } catch (error) {
        console.error(`Error fetching roles for subscription ${subscription.subscriptionId}:`, error);
      }
    }

    return { value: allRoles };
  } catch (error) {
    console.error('Error getting Azure resource PIM roles:', error);
    throw error;
  }
}

// Function to get all roles (both directory and Azure resource roles)
async function getAllRoles() {
  try {
    const results = {
      directoryRoles: { value: [] },
      azureResourceRoles: { value: [] },
      errors: []
    };

    // Try to get directory roles
    try {
      const directoryRoles = await getPimRoles();
      results.directoryRoles = directoryRoles;
    } catch (error) {
      console.error('Error fetching directory roles:', error);
      results.errors.push({ type: 'directory', error: error.toString() });
    }

    // Try to get Azure resource roles
    try {
      const azureResourceRoles = await getAzureResourceRoles();
      results.azureResourceRoles = azureResourceRoles;
    } catch (error) {
      console.error('Error fetching Azure resource roles:', error);
      results.errors.push({ type: 'azureResource', error: error.toString() });
    }

    return results;
  } catch (error) {
    console.error('Error getting all roles:', error);
    throw error;
  }
}

// Function to get active directory roles
async function getActiveDirectoryRoles() {
  try {
    // Get token from storage
    const { graphToken: encryptedToken, tokenTimestamp } =
      await browser.storage.local.get(['graphToken', 'tokenTimestamp']);

    if (!encryptedToken) {
      throw new Error('No Microsoft Graph token found. Please visit a Microsoft service like portal.azure.com first.');
    }
    
    // Decrypt the token
    const graphToken = await decryptToken(encryptedToken);
    
    if (!graphToken) {
      throw new Error('Failed to decrypt token. Please clear tokens and re-authenticate.');
    }

    // Check if token is older than 45 minutes
    if (!tokenTimestamp) {
      throw new Error('Token timestamp missing. Please re-authenticate.');
    }
    const tokenAgeInMinutes = (Date.now() - tokenTimestamp) / (1000 * 60);
    if (tokenAgeInMinutes > 45) {
      throw new Error('Token may have expired. Please refresh your Microsoft service session.');
    }

    console.log('Using captured token to fetch active directory roles');

    // Extract principalId from token
    const principalId = extractPrincipalId(graphToken);

    if (!principalId) {
      throw new Error('Could not extract user ID from token. Please refresh your session.');
    }

    console.log('Using principalId:', principalId);

    // Use roleAssignmentScheduleInstances to get currently active assignments
    // This is more accurate than roleAssignmentScheduleRequests which includes historical data
    const response = await fetch(
      `https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances/filterByCurrentUser(on='principal')`,
      {
        method: "GET",
        headers: {
          'Authorization': `Bearer ${graphToken}`,
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      }
    );

    if (!response.ok) {
      throw new Error(`API call failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();

    console.log('Active directory roles API response:', data);

    // Filter for only active PIM assignments (time-bound assignments)
    if (data && data.value && Array.isArray(data.value)) {
      const now = new Date();
      
      data.value = data.value.filter(role => {
        if (!role) return false;
        
        // Check if this is a time-bound assignment (PIM activation, not permanent)
        const startDateTime = role.startDateTime;
        const endDateTime = role.endDateTime;
        
        // Must have both start and end times for PIM activations
        if (!startDateTime || !endDateTime) {
          return false; // Skip permanent assignments
        }
        
        const start = new Date(startDateTime);
        const end = new Date(endDateTime);
        
        // Only include if currently active (started and not expired)
        return start <= now && end > now;
      });

      // Resolve role definition names
      if (data.value.length > 0) {
        const roleDefinitions = await getRoleDefinitions(graphToken);

        data.value = data.value.map(role => {
          if (!role) return role;
          if (role.roleDefinitionId && roleDefinitions[role.roleDefinitionId]) {
            role.roleName = roleDefinitions[role.roleDefinitionId];
          }
          return role;
        });
      }
    } else {
      // Return empty result if data structure is invalid
      console.warn('Invalid data structure in active directory roles response');
      return { value: [] };
    }

    return data;
  } catch (error) {
    console.error('Error getting active directory roles:', error);
    console.error('Error stack:', error.stack);
    console.error('Error details:', {
      message: error.message,
      name: error.name,
      fileName: error.fileName,
      lineNumber: error.lineNumber
    });
    throw error;
  }
}

// Function to get active Azure resource roles
async function getActiveAzureResourceRoles() {
  try {
    // Get token from storage
    const { azureManagementToken: encryptedToken, azureManagementTokenTimestamp } =
      await browser.storage.local.get(['azureManagementToken', 'azureManagementTokenTimestamp']);

    if (!encryptedToken) {
      throw new Error('No Azure Management token found. Please visit Azure Portal first.');
    }
    
    // Decrypt the token
    const azureManagementToken = await decryptToken(encryptedToken);
    
    if (!azureManagementToken) {
      throw new Error('Failed to decrypt Azure Management token. Please clear tokens and re-authenticate.');
    }

    // Check if token is older than 45 minutes
    if (!azureManagementTokenTimestamp) {
      throw new Error('Token timestamp missing. Please re-authenticate.');
    }
    const tokenAgeInMinutes = (Date.now() - azureManagementTokenTimestamp) / (1000 * 60);
    if (tokenAgeInMinutes > 45) {
      throw new Error('Token may have expired. Please refresh your Azure Portal session.');
    }

    console.log('Using captured token to fetch active Azure resource roles');

    // Extract principalId from token
    const principalId = extractPrincipalId(azureManagementToken);

    if (!principalId) {
      throw new Error('Could not extract user ID from token. Please refresh your session.');
    }

    console.log('Using principalId:', principalId);

    // First, get all subscriptions the user has access to
    const subscriptionsResponse = await fetch(
      'https://management.azure.com/subscriptions?api-version=2020-01-01',
      {
        method: "GET",
        headers: {
          'Authorization': `Bearer ${azureManagementToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (!subscriptionsResponse.ok) {
      if (subscriptionsResponse.status === 401) {
        throw new Error('Azure Management token expired or invalid. Please visit Azure Portal (portal.azure.com), navigate around to refresh your session, then click Refresh in this extension.');
      }
      throw new Error(`Subscriptions API call failed: ${subscriptionsResponse.status} ${subscriptionsResponse.statusText}`);
    }

    const subscriptionsData = await subscriptionsResponse.json();

    if (!subscriptionsData.value || subscriptionsData.value.length === 0) {
      return { value: [] }; // No subscriptions found
    }

    // Fetch active role assignment requests for each subscription
    const allActiveRoles = [];

    for (const subscription of subscriptionsData.value) {
      // Validate subscription object
      if (!subscription || !subscription.subscriptionId) {
        console.warn('Skipping invalid subscription object:', subscription);
        continue;
      }
      
      try {
        // Use roleAssignmentScheduleInstances to get currently active PIM role assignments
        const response = await fetch(
          `https://management.azure.com/subscriptions/${subscription.subscriptionId}/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01&$filter=asTarget()`,
          {
            method: "GET",
            headers: {
              'Authorization': `Bearer ${azureManagementToken}`,
              'Content-Type': 'application/json',
              'Cache-Control': 'no-cache, no-store, must-revalidate',
              'Pragma': 'no-cache'
            }
          }
        );

        if (response.ok) {
          const data = await response.json();
          
          console.log(`Active Azure roles for subscription ${subscription.subscriptionId}:`, data);

          if (data && data.value && Array.isArray(data.value) && data.value.length > 0) {
            // Filter for only active PIM assignments (those with assignmentType indicating PIM activation)
            let activeRoles = data.value.filter(role => {
              // Ensure role and properties exist
              if (!role || !role.properties) {
                return false;
              }
              
              // Check if this is a time-bound assignment (PIM activation)
              const endDateTime = role.properties.endDateTime;
              const assignmentType = role.properties.assignmentType;
              
              // Include if it has an end date (time-bound = PIM) or is marked as "Activated"
              return endDateTime || assignmentType === 'Activated';
            });

            // Filter out expired roles
            const now = new Date();
            activeRoles = activeRoles.filter(role => {
              if (!role || !role.properties) {
                return false;
              }
              
              const endDateTime = role.properties.endDateTime;
              if (endDateTime) {
                return new Date(endDateTime) > now;
              }
              // Keep roles without endDateTime (permanent assignments)
              return true;
            });

            // Add subscription context to each role
            activeRoles.forEach(role => {
              if (role) {
                role.subscriptionId = subscription.subscriptionId;
                role.subscriptionName = subscription.displayName;
                role.roleType = 'azureResource'; // Mark as Azure resource role
              }
            });

            allActiveRoles.push(...activeRoles);
          }
        } else {
          console.warn(`Failed to fetch active roles for subscription ${subscription.subscriptionId}: ${response.status}`);
        }
      } catch (error) {
        console.error(`Error fetching active roles for subscription ${subscription.subscriptionId}:`, error);
      }
    }

    return { value: allActiveRoles };
  } catch (error) {
    console.error('Error getting active Azure resource roles:', error);
    console.error('Error stack:', error.stack);
    console.error('Error details:', {
      message: error.message,
      name: error.name,
      fileName: error.fileName,
      lineNumber: error.lineNumber
    });
    throw error;
  }
}

// Function to get all active roles (both directory and Azure resource)
async function getActiveRoles() {
  try {
    const results = {
      activeDirectoryRoles: { value: [] },
      activeAzureResourceRoles: { value: [] },
      errors: []
    };

    // Try to get active directory roles
    try {
      const activeDirectoryRoles = await getActiveDirectoryRoles();
      results.activeDirectoryRoles = activeDirectoryRoles;
    } catch (error) {
      console.error('Error fetching active directory roles:', error);
      results.errors.push({ type: 'activeDirectory', error: error.toString() });
    }

    // Try to get active Azure resource roles
    try {
      const activeAzureResourceRoles = await getActiveAzureResourceRoles();
      results.activeAzureResourceRoles = activeAzureResourceRoles;
      console.log('Active Azure Resource Roles fetched:', activeAzureResourceRoles);
    } catch (error) {
      console.error('Error fetching active Azure resource roles:', error);
      results.errors.push({ type: 'activeAzureResource', error: error.toString() });
    }

    console.log('getActiveRoles returning:', results);
    return results;
  } catch (error) {
    console.error('Error getting all active roles:', error);
    throw error;
  }
}
