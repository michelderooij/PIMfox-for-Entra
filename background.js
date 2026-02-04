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

// Listen for web requests to PIM API
browser.webRequest.onBeforeRequest.addListener(
  function(details) {
    // Skip extension's own requests
    if (details.tabId === -1) {
      return;
    }
    
    if (details.url.includes('api.azrbac.mspim.azure.com')) {
      // We found a request to PIM API from a portal page
      captureAuthToken(details.requestId, details.url);
    }
  },
  {urls: ["https://api.azrbac.mspim.azure.com/*"]}
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

// Capture PIM API token from request headers
browser.webRequest.onSendHeaders.addListener(
  function(details) {
    // Skip requests made by the extension itself
    if (details.tabId === -1) {
      return;
    }
    
    if (details.url.includes('api.azrbac.mspim.azure.com')) {
      const authHeader = details.requestHeaders.find(header =>
        header.name.toLowerCase() === 'authorization'
      );

      if (authHeader && authHeader.value.startsWith('Bearer ')) {
        // Extract the token (remove "Bearer " prefix)
        const token = authHeader.value.substring(7);

        // Encrypt and store the PIM API token separately
        encryptToken(token).then(encryptedToken => {
          browser.storage.local.set({
            pimToken: encryptedToken,
            pimTokenTimestamp: Date.now(),
            pimTokenSource: details.url
          });
          console.log('PIM API token captured and encrypted from portal!');
        }).catch(error => {
          console.error('Failed to encrypt PIM token:', error);
        });
      }
    }
  },
  {urls: ["https://api.azrbac.mspim.azure.com/*"]},
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
    // Get all tokens for role activation/deactivation
    browser.storage.local.get(['graphToken', 'azureManagementToken', 'pimToken'])
      .then(async (result) => {
        const tokens = {};
        
        if (result.graphToken) {
          tokens.graphToken = await decryptToken(result.graphToken);
        }
        
        if (result.azureManagementToken) {
          tokens.azureManagementToken = await decryptToken(result.azureManagementToken);
        }
        
        if (result.pimToken) {
          tokens.pimToken = await decryptToken(result.pimToken);
        }
        
        sendResponse({ success: true, tokens: tokens });
      })
      .catch(error => sendResponse({ success: false, error: error.toString() }));
    return true;
  }
});

// Cache for group names to avoid repeated API calls
let groupNamesCache = {};
let groupNamesCacheTime = null;
const GROUP_NAMES_CACHE_VALIDITY_MS = 300000; // 5 minutes

// Function to resolve group IDs to group names using Graph API
async function resolveGroupNames(groupIds) {
  if (!groupIds || groupIds.length === 0) return {};
  
  // Check cache first
  const now = Date.now();
  if (groupNamesCacheTime && (now - groupNamesCacheTime) < GROUP_NAMES_CACHE_VALIDITY_MS) {
    // Return cached names for known IDs
    const cachedResults = {};
    let allCached = true;
    for (const id of groupIds) {
      if (groupNamesCache[id]) {
        cachedResults[id] = groupNamesCache[id];
      } else {
        allCached = false;
      }
    }
    if (allCached) {
      console.log('Using cached group names');
      return cachedResults;
    }
  }
  
  try {
    // Get Graph token
    const { graphToken: encryptedGraphToken } = await browser.storage.local.get(['graphToken']);
    if (!encryptedGraphToken) {
      console.warn('No Graph token for group name resolution');
      return {};
    }
    
    const graphToken = await decryptToken(encryptedGraphToken);
    if (!graphToken) {
      console.warn('Failed to decrypt Graph token for group name resolution');
      return {};
    }
    
    const results = {};
    
    // Fetch each group's details (batch if needed for large sets)
    for (const groupId of groupIds) {
      if (groupNamesCache[groupId]) {
        results[groupId] = groupNamesCache[groupId];
        continue;
      }
      
      try {
        const response = await fetch(
          `https://graph.microsoft.com/v1.0/groups/${groupId}?$select=displayName`,
          {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${graphToken}`,
              'Content-Type': 'application/json'
            }
          }
        );
        
        if (response.ok) {
          const group = await response.json();
          if (group.displayName) {
            results[groupId] = group.displayName;
            groupNamesCache[groupId] = group.displayName;
          }
        } else {
          console.warn(`Failed to fetch group ${groupId}: ${response.status}`);
        }
      } catch (err) {
        console.warn(`Error fetching group ${groupId}:`, err);
      }
    }
    
    groupNamesCacheTime = Date.now();
    return results;
  } catch (error) {
    console.error('Error resolving group names:', error);
    return {};
  }
}

// Function to get PIM group eligibilities
async function getPimGroupEligibilities() {
  try {
    // Get PIM token and Graph token from storage
    // PIM token is captured when user browses to PIM Groups in Azure Portal
    const { graphToken: encryptedGraphToken, pimToken: encryptedPimToken, pimTokenTimestamp } = 
      await browser.storage.local.get(['graphToken', 'pimToken', 'pimTokenTimestamp']);
    
    // PIM Groups requires the special PIM API token, not the Graph token
    if (!encryptedPimToken) {
      console.warn('No PIM token available. Please browse to PIM > Groups in Azure Portal to capture the token.');
      return { value: [], permissionDenied: true, needsPimToken: true };
    }
    
    // Decrypt the PIM token
    const pimToken = await decryptToken(encryptedPimToken);
    
    if (!pimToken) {
      throw new Error('Failed to decrypt PIM token.');
    }
    
    // Check token age
    if (pimTokenTimestamp) {
      const tokenAgeInMinutes = (Date.now() - pimTokenTimestamp) / (1000 * 60);
      if (tokenAgeInMinutes > 45) {
        console.warn('PIM token may have expired. Please refresh the PIM Groups page in Azure Portal.');
        return { value: [], permissionDenied: true, tokenExpired: true };
      }
    }
    
    // Extract principalId from PIM token (or Graph token as fallback)
    let principalId = extractPrincipalId(pimToken);
    if (!principalId && encryptedGraphToken) {
      const graphToken = await decryptToken(encryptedGraphToken);
      principalId = extractPrincipalId(graphToken);
    }
    if (!principalId) {
      throw new Error('Could not extract user ID from token.');
    }
    
    console.log('Fetching PIM group eligibilities using PIM API');
    
    // Use the PIM API endpoint (same as Azure Portal uses)
    const filter = encodeURIComponent(`(subject/id eq '${principalId}') and (assignmentState eq 'Eligible')`);
    const expand = encodeURIComponent('linkedEligibleRoleAssignment,subject,scopedResource,roleDefinition($expand=resource)');
    
    const response = await fetch(
      `https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/roleAssignments?$expand=${expand}&$filter=${filter}&$count=true`,
      {
        method: "GET",
        headers: {
          'Authorization': `Bearer ${pimToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    if (!response.ok) {
      if (response.status === 403 || response.status === 401) {
        console.warn('PIM group eligibilities fetch failed - permission denied. Status:', response.status);
        return { value: [], permissionDenied: true };
      }
      throw new Error(`API call failed: ${response.status} ${response.statusText}`);
    }
    
    const data = await response.json();
    
    // Transform the response to match our expected format
    const transformedData = { value: [] };
    
    if (data.value && data.value.length > 0) {
      // Helper to extract group ID from various possible response fields
      const extractGroupId = (assignment) => {
        return assignment.scopedResource?.id || 
               assignment.resourceId || 
               assignment.resource?.id ||
               assignment.scopedResourceId ||
               assignment.roleDefinition?.resource?.id || '';
      };
      
      // Collect group IDs that need name resolution
      const groupIdsNeedingNames = [];
      data.value.forEach(assignment => {
        const groupId = extractGroupId(assignment);
        const hasName = assignment.scopedResource?.displayName && 
                        assignment.scopedResource.displayName !== 'Unknown Group';
        if (groupId && !hasName) {
          groupIdsNeedingNames.push(groupId);
        }
      });
      
      // Resolve group names from Graph API if needed
      let resolvedNames = {};
      if (groupIdsNeedingNames.length > 0) {
        console.log(`Resolving ${groupIdsNeedingNames.length} group name(s) from Graph API`);
        resolvedNames = await resolveGroupNames(groupIdsNeedingNames);
      }
      
      transformedData.value = data.value.map(assignment => {
        const groupId = extractGroupId(assignment);
        let groupName = assignment.scopedResource?.displayName || assignment.scopedResource?.externalId;
        
        // If no name from PIM API, try resolved names
        if (!groupName || groupName === 'Unknown Group') {
          groupName = resolvedNames[groupId] || 'Unknown Group';
        }
        
        // Extract role definition ID
        const roleDefId = assignment.roleDefinition?.id || assignment.roleDefinitionId;
        const accessType = assignment.roleDefinition?.displayName === 'Owner' ? 'owner' : 'member';
        
        return {
          groupId: groupId,
          groupName: groupName,
          principalId: assignment.subject?.id || principalId,
          accessId: accessType,
          roleDefinitionId: roleDefId,
          assignmentType: 'group',
          assignmentId: assignment.id,
          startDateTime: assignment.startDateTime,
          endDateTime: assignment.endDateTime
        };
      });
    }
    
    return transformedData;
  } catch (error) {
    console.error('Error getting PIM group eligibilities:', error);
    return { value: [], error: error.toString() };
  }
}

// Function to get active PIM group memberships
async function getActiveGroupMemberships() {
  try {
    // Get PIM token and Graph token from storage
    const { graphToken: encryptedGraphToken, pimToken: encryptedPimToken, pimTokenTimestamp } = 
      await browser.storage.local.get(['graphToken', 'pimToken', 'pimTokenTimestamp']);
    
    // PIM Groups requires the special PIM API token
    if (!encryptedPimToken) {
      console.warn('No PIM token available for active group memberships.');
      return { value: [], permissionDenied: true, needsPimToken: true };
    }
    
    // Decrypt the PIM token
    const pimToken = await decryptToken(encryptedPimToken);
    
    if (!pimToken) {
      throw new Error('Failed to decrypt PIM token.');
    }
    
    // Check token age
    if (pimTokenTimestamp) {
      const tokenAgeInMinutes = (Date.now() - pimTokenTimestamp) / (1000 * 60);
      if (tokenAgeInMinutes > 45) {
        console.warn('PIM token may have expired.');
        return { value: [], permissionDenied: true, tokenExpired: true };
      }
    }
    
    // Extract principalId from PIM token (or Graph token as fallback)
    let principalId = extractPrincipalId(pimToken);
    if (!principalId && encryptedGraphToken) {
      const graphToken = await decryptToken(encryptedGraphToken);
      principalId = extractPrincipalId(graphToken);
    }
    if (!principalId) {
      throw new Error('Could not extract user ID from token.');
    }
    
    console.log('Fetching active PIM group memberships using PIM API');
    
    // Use the PIM API endpoint for active assignments
    const filter = encodeURIComponent(`(subject/id eq '${principalId}') and (assignmentState eq 'Active')`);
    const expand = encodeURIComponent('linkedEligibleRoleAssignment,subject,scopedResource,roleDefinition($expand=resource)');
    
    const response = await fetch(
      `https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/roleAssignments?$expand=${expand}&$filter=${filter}&$count=true`,
      {
        method: "GET",
        headers: {
          'Authorization': `Bearer ${pimToken}`,
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      }
    );
    
    if (!response.ok) {
      if (response.status === 403 || response.status === 401) {
        console.warn('Active PIM group memberships fetch failed - permission denied. Status:', response.status);
        return { value: [], permissionDenied: true };
      }
      throw new Error(`API call failed: ${response.status} ${response.statusText}`);
    }
    
    const data = await response.json();
    
    // Transform the response to match our expected format
    const transformedData = { value: [] };
    
    if (data.value && data.value.length > 0) {
      const now = new Date();
      
      // Filter for currently active assignments
      const activeAssignments = data.value.filter(assignment => {
        const startDateTime = assignment.startDateTime;
        const endDateTime = assignment.endDateTime;
        
        if (!startDateTime) return false;
        
        const start = new Date(startDateTime);
        const end = endDateTime ? new Date(endDateTime) : null;
        
        if (end) {
          return start <= now && end > now;
        } else {
          return start <= now;
        }
      });
      
      // Helper to extract group ID
      const extractGroupId = (assignment) => {
        return assignment.scopedResource?.id || 
               assignment.resourceId || 
               assignment.resource?.id ||
               assignment.scopedResourceId ||
               assignment.roleDefinition?.resource?.id || '';
      };
      
      // Collect group IDs that need name resolution
      const groupIdsNeedingNames = [];
      activeAssignments.forEach(assignment => {
        const groupId = extractGroupId(assignment);
        const hasName = assignment.scopedResource?.displayName && 
                        assignment.scopedResource.displayName !== 'Unknown Group';
        if (groupId && !hasName) {
          groupIdsNeedingNames.push(groupId);
        }
      });
      
      // Resolve group names from Graph API if needed
      let resolvedNames = {};
      if (groupIdsNeedingNames.length > 0) {
        console.log(`Resolving ${groupIdsNeedingNames.length} active group name(s) from Graph API`);
        resolvedNames = await resolveGroupNames(groupIdsNeedingNames);
      }
      
      transformedData.value = activeAssignments.map(assignment => {
        const groupId = extractGroupId(assignment);
        let groupName = assignment.scopedResource?.displayName || assignment.scopedResource?.externalId;
        
        // If no name from PIM API, try resolved names
        if (!groupName || groupName === 'Unknown Group') {
          groupName = resolvedNames[groupId] || 'Unknown Group';
        }
        
        // Extract role definition ID
        const roleDefId = assignment.roleDefinition?.id || assignment.roleDefinitionId;
        const accessType = assignment.roleDefinition?.displayName === 'Owner' ? 'owner' : 'member';
        
        return {
          groupId: groupId,
          groupName: groupName,
          principalId: assignment.subject?.id || principalId,
          accessId: accessType,
          roleDefinitionId: roleDefId,
          assignmentType: 'group',
          assignmentId: assignment.id,
          startDateTime: assignment.startDateTime,
          endDateTime: assignment.endDateTime
        };
      });
    }
    
    return transformedData;
  } catch (error) {
    console.error('Error getting active PIM group memberships:', error);
    return { value: [], error: error.toString() };
  }
}

// Function to get PIM roles using the stored token
async function getPimRoles() {
  try {
    // Get Graph token from storage - this is all we need now
    const { graphToken: encryptedGraphToken, tokenTimestamp } = 
      await browser.storage.local.get(['graphToken', 'tokenTimestamp']);
    
    if (!encryptedGraphToken) {
      console.warn('No Graph token available for PIM directory roles.');
      return { value: [], permissionDenied: true };
    }
    
    // Decrypt the Graph token
    const graphToken = await decryptToken(encryptedGraphToken);
    
    if (!graphToken) {
      throw new Error('Failed to decrypt Graph token. Please clear tokens and re-authenticate.');
    }
    
    // Check if token is older than 45 minutes (tokens typically expire after 1 hour)
    if (tokenTimestamp) {
      const tokenAgeInMinutes = (Date.now() - tokenTimestamp) / (1000 * 60);
      if (tokenAgeInMinutes > 45) {
        console.warn('Graph token may have expired.');
      }
    }
    
    console.log('Fetching PIM directory role eligibilities using Graph API');
    
    // Extract principalId from Graph token
    const principalId = extractPrincipalId(graphToken);
    
    if (!principalId) {
      throw new Error('Could not extract user ID from token. Please refresh your session.');
    }
    
    console.log('Using principalId:', principalId);
    
    // Use Microsoft Graph API for directory role eligibilities
    const filter = encodeURIComponent(`principalId eq '${principalId}'`);
    
    const response = await fetch(
      `https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$filter=${filter}&$expand=roleDefinition`, 
      {
        method: "GET",
        headers: {
          'Authorization': `Bearer ${graphToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        console.warn('PIM directory roles fetch failed - permission denied or invalid token. Status:', response.status);
        return { value: [], permissionDenied: true };
      }
      throw new Error(`API call failed: ${response.status} ${response.statusText}`);
    }
    
    const data = await response.json();
    
    // Transform Graph API response to match expected format
    const transformedData = {
      value: (data.value || []).map(assignment => ({
        id: assignment.id,
        roleDefinitionId: assignment.roleDefinitionId,
        roleName: assignment.roleDefinition?.displayName,
        principalId: assignment.principalId || principalId,
        directoryScopeId: assignment.directoryScopeId || '/',
        scopeDisplayName: assignment.directoryScopeId === '/' ? 'Directory' : assignment.directoryScopeId,
        scheduleInfo: {
          startDateTime: assignment.startDateTime,
          expiration: {
            endDateTime: assignment.endDateTime,
            type: assignment.endDateTime ? 'afterDateTime' : 'noExpiration'
          }
        },
        memberType: assignment.memberType || 'Direct',
        assignmentType: 'direct'
      }))
    };
    
    return transformedData;
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

// Function to clear the stored token
async function clearToken() {
  await browser.storage.local.remove([
    'graphToken', 'tokenTimestamp', 'tokenSource',
    'azureManagementToken', 'azureManagementTokenTimestamp', 'azureManagementTokenSource',
    'pimToken', 'pimTokenTimestamp', 'pimTokenSource'
  ]);
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
      groupEligibilities: { value: [] },
      errors: []
    };

    // Try to get directory roles
    try {
      const directoryRoles = await getPimRoles();
      results.directoryRoles = directoryRoles;
      
      // Add warning if permission was denied
      if (directoryRoles.permissionDenied) {
        results.errors.push({ 
          type: 'directory', 
          error: 'Could not fetch directory roles - please browse to Azure Portal first.',
          warning: true
        });
      }
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

    // Try to get PIM group eligibilities
    try {
      const groupEligibilities = await getPimGroupEligibilities();
      results.groupEligibilities = groupEligibilities;
      
      // Add specific warning if PIM token is needed
      if (groupEligibilities.needsPimToken) {
        results.errors.push({ 
          type: 'groupEligibilities', 
          error: 'PIM Groups require a separate token. Please browse to PIM > Groups in Azure Portal to capture the token.',
          warning: true
        });
      } else if (groupEligibilities.tokenExpired) {
        results.errors.push({ 
          type: 'groupEligibilities', 
          error: 'PIM token may have expired. Please refresh the PIM Groups page in Azure Portal.',
          warning: true
        });
      } else if (groupEligibilities.permissionDenied) {
        results.errors.push({ 
          type: 'groupEligibilities', 
          error: 'Could not fetch group eligibilities - please browse to PIM > Groups in Azure Portal.',
          warning: true
        });
      } else if (groupEligibilities.error) {
        results.errors.push({ type: 'groupEligibilities', error: groupEligibilities.error, warning: true });
      }
    } catch (error) {
      console.error('Error fetching group eligibilities:', error);
      results.errors.push({ type: 'groupEligibilities', error: error.toString(), warning: true });
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
    // Get Graph token from storage - this is all we need now
    const { graphToken: encryptedGraphToken, tokenTimestamp } =
      await browser.storage.local.get(['graphToken', 'tokenTimestamp']);

    if (!encryptedGraphToken) {
      console.warn('No Graph token available for active directory roles.');
      return { value: [], permissionDenied: true };
    }
    
    // Decrypt the Graph token
    const graphToken = await decryptToken(encryptedGraphToken);
    
    if (!graphToken) {
      throw new Error('Failed to decrypt Graph token. Please clear tokens and re-authenticate.');
    }

    // Check if token is older than 45 minutes
    if (tokenTimestamp) {
      const tokenAgeInMinutes = (Date.now() - tokenTimestamp) / (1000 * 60);
      if (tokenAgeInMinutes > 45) {
        console.warn('Graph token may have expired.');
      }
    }

    console.log('Fetching active directory roles using Graph API');

    // Extract principalId from Graph token
    const principalId = extractPrincipalId(graphToken);

    if (!principalId) {
      throw new Error('Could not extract user ID from token. Please refresh your session.');
    }

    console.log('Using principalId:', principalId);

    // Use Microsoft Graph API for active directory role assignments
    const filter = encodeURIComponent(`principalId eq '${principalId}'`);

    const response = await fetch(
      `https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$filter=${filter}&$expand=roleDefinition`,
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
      if (response.status === 401 || response.status === 403) {
        console.warn('Active directory roles fetch failed - permission denied or invalid token. Status:', response.status);
        return { value: [], permissionDenied: true };
      }
      throw new Error(`API call failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();

    console.log('Active directory roles API response:', data);

    // Filter for only time-bound assignments (PIM activations, not permanent)
    const now = new Date();
    const filteredValue = (data.value || []).filter(assignment => {
      // Must have endDateTime for PIM activations (not permanent)
      if (!assignment.endDateTime) {
        return false;
      }
      const end = new Date(assignment.endDateTime);
      return end > now;
    });

    // Transform Graph API response to match expected format
    const transformedData = {
      value: filteredValue.map(assignment => ({
        id: assignment.id,
        roleDefinitionId: assignment.roleDefinitionId,
        roleName: assignment.roleDefinition?.displayName,
        principalId: assignment.principalId || principalId,
        directoryScopeId: assignment.directoryScopeId || '/',
        scopeDisplayName: assignment.directoryScopeId === '/' ? 'Directory' : assignment.directoryScopeId,
        startDateTime: assignment.startDateTime,
        endDateTime: assignment.endDateTime,
        memberType: assignment.memberType || 'Direct',
        assignmentType: 'direct'
      }))
    };

    return transformedData;
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
      activeGroupMemberships: { value: [] },
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

    // Try to get active group memberships
    try {
      const activeGroupMemberships = await getActiveGroupMemberships();
      results.activeGroupMemberships = activeGroupMemberships;
      
      // Add specific warning if PIM token is needed
      if (activeGroupMemberships.needsPimToken) {
        results.errors.push({ 
          type: 'activeGroupMemberships', 
          error: 'PIM Groups require a separate token. Please browse to PIM > Groups in Azure Portal.',
          warning: true
        });
      } else if (activeGroupMemberships.tokenExpired) {
        results.errors.push({ 
          type: 'activeGroupMemberships', 
          error: 'PIM token may have expired. Please refresh the PIM Groups page in Azure Portal.',
          warning: true
        });
      } else if (activeGroupMemberships.permissionDenied) {
        results.errors.push({ 
          type: 'activeGroupMemberships', 
          error: 'Could not fetch active group memberships - please browse to PIM > Groups in Azure Portal.',
          warning: true
        });
      } else if (activeGroupMemberships.error) {
        results.errors.push({ type: 'activeGroupMemberships', error: activeGroupMemberships.error, warning: true });
      }
    } catch (error) {
      console.error('Error fetching active group memberships:', error);
      results.errors.push({ type: 'activeGroupMemberships', error: error.toString(), warning: true });
    }

    console.log('getActiveRoles returning:', results);
    return results;
  } catch (error) {
    console.error('Error getting all active roles:', error);
    throw error;
  }
}
