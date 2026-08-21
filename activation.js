/**
 * Role Activation API Module
 * Handles PIM role activation requests to Microsoft Graph API
 */

// Function to activate selected PIM roles
async function activatePimRoles(selectedRoles, durationHours, justification, token, ticketInfo = {}) {
  if (!token) {
    throw new Error('No access token available');
  }

  if (!selectedRoles || selectedRoles.length === 0) {
    throw new Error('No roles selected for activation');
  }

  if (!justification || justification.trim() === '') {
    throw new Error('Justification is required');
  }

  if (durationHours <= 0) {
    throw new Error('Duration must be greater than 0 hours');
  }

  // Convert duration from hours to ISO 8601 duration format
  const isoDuration = `PT${Math.round(durationHours * 60)}M`; // Convert to minutes for more precision

  // Current time in ISO format
  const startDateTime = new Date().toISOString();

  // Process each role activation request
  const results = [];
  const errors = [];
  const skipped = [];

  for (const role of selectedRoles) {
    try {
      // Prepare request body
      const requestBody = {
        "action": "selfActivate",
        "principalId": role.principalId,
        "roleDefinitionId": role.roleDefinitionId,
        "directoryScopeId": role.directoryScopeId || "/",
        "justification": justification,
        "scheduleInfo": {
          "startDateTime": startDateTime,
          "expiration": {
            "type": "AfterDuration",
            "duration": isoDuration
          }
        }
      };

      // Add ticket info if both system and number are provided
      if (ticketInfo.ticketSystem || ticketInfo.ticketNumber) {
        requestBody.ticketInfo = {
          "ticketSystem": ticketInfo.ticketSystem || "Self-Service",
          "ticketNumber": ticketInfo.ticketNumber || "N/A"
        };
      }

      // Send activation request to Graph API
      const response = await fetch(
        'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests',
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(requestBody)
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        const errorMessage = errorData.error?.message || 'Unknown error';
        
        // Check if role is already activated
        if (response.status === 400 && errorMessage.includes('already exists')) {
          skipped.push({
            role: role.roleName || role.roleDefinitionId,
            reason: 'Already activated'
          });
          continue; // Skip to next role
        }
        
        throw new Error(
          `API error (${response.status}): ${errorMessage}`
        );
      }

      const responseData = await response.json();
      results.push({
        role: role.roleName || role.roleDefinitionId,
        success: true,
        requestId: responseData.id
      });

    } catch (error) {
      console.error('Role activation error:', error);
      errors.push({
        role: role.roleName || role.roleDefinitionId,
        success: false,
        error: error.message
      });
    }
  }

  return {
    success: errors.length === 0,
    results: results,
    errors: errors,
    skipped: skipped
  };
}

// Function to get currently selected roles from DOM
function getSelectedRoles() {
  return Array.from(document.querySelectorAll('.role-checkbox:checked'))
    .map(checkbox => {
      // Get the parent role item
      const roleItem = checkbox.closest('.role-item');
      if (!roleItem) return null;
      
      // Extract role information from data attributes
      const roleId = checkbox.id.replace('-checkbox', '');
      
      // Find data stored in browser.storage
      return {
        roleId: roleId,
        // These properties will be filled from the roles data in popup.js
        roleDefinitionId: roleItem.dataset.roleDefinitionId,
        principalId: roleItem.dataset.principalId,
        directoryScopeId: roleItem.dataset.directoryScopeId,
        roleName: roleItem.querySelector('.role-title').textContent
      };
    })
    .filter(role => role !== null);
}

// Validates an ARM scope path so it cannot be used to construct an unexpected URL.
// Expected forms: /subscriptions/{guid}[/resourceGroups/{name}[/providers/...]]
const ARM_SCOPE_RE = /^\/subscriptions\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(\/[^?#]*)?$/i;
function validateArmScope(scope) {
  if (!scope || typeof scope !== 'string' || !ARM_SCOPE_RE.test(scope)) {
    throw new Error(`Invalid ARM scope value: "${scope}"`);
  }
  return scope;
}

// Function to activate Azure resource PIM roles
async function activateAzureResourceRoles(selectedRoles, durationHours, justification, azureManagementToken, ticketInfo = {}) {
  if (!azureManagementToken) {
    throw new Error('No Azure Management token available');
  }

  if (!selectedRoles || selectedRoles.length === 0) {
    throw new Error('No roles selected for activation');
  }

  if (!justification || justification.trim() === '') {
    throw new Error('Justification is required');
  }

  if (durationHours <= 0) {
    throw new Error('Duration must be greater than 0 hours');
  }

  // Convert duration from hours to ISO 8601 duration format
  const isoDuration = `PT${Math.round(durationHours * 60)}M`; // Convert to minutes for more precision

  // Current time in ISO format
  const startDateTime = new Date().toISOString();

  // Process each role activation request
  const results = [];
  const errors = [];
  const skipped = [];

  for (const role of selectedRoles) {
    try {
      // Generate a new GUID for the request
      const requestId = generateGuid();

      // Extract and validate scope before using it in a URL path.
      const scope = validateArmScope(role.properties?.scope || `/subscriptions/${role.subscriptionId}`);

      // Prepare request body for Azure Resource Manager API
      const requestBody = {
        "properties": {
          "principalId": role.properties?.principalId || role.principalId,
          "roleDefinitionId": role.properties?.roleDefinitionId || role.roleDefinitionId,
          "requestType": "SelfActivate",
          "justification": justification,
          "scheduleInfo": {
            "startDateTime": startDateTime,
            "expiration": {
              "type": "AfterDuration",
              "endDateTime": null,
              "duration": isoDuration
            }
          }
        }
      };

      // Add ticket info if provided
      if (ticketInfo.ticketSystem || ticketInfo.ticketNumber) {
        requestBody.properties.ticketInfo = {
          "ticketSystem": ticketInfo.ticketSystem || "Self-Service",
          "ticketNumber": ticketInfo.ticketNumber || "N/A"
        };
      }

      // Send activation request to Azure Management API
      const response = await fetch(
        `https://management.azure.com${scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/${requestId}?api-version=2020-10-01`,
        {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${azureManagementToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(requestBody)
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        const errorMessage = errorData.error?.message || 'Unknown error';
        
        // Check if role is already activated
        if (response.status === 400 && errorMessage.includes('already exists')) {
          skipped.push({
            role: role.roleName || role.properties?.expandedProperties?.roleDefinition?.displayName || 'Unknown Role',
            scope: role.subscriptionName || scope,
            reason: 'Already activated'
          });
          continue; // Skip to next role
        }
        
        throw new Error(
          `API error (${response.status}): ${errorMessage}`
        );
      }

      const responseData = await response.json();
      results.push({
        role: role.roleName || role.properties?.expandedProperties?.roleDefinition?.displayName || 'Unknown Role',
        scope: role.subscriptionName || scope,
        success: true,
        requestId: responseData.name
      });

    } catch (error) {
      console.error('Azure resource role activation error:', error);
      errors.push({
        role: role.roleName || role.properties?.expandedProperties?.roleDefinition?.displayName || 'Unknown Role',
        scope: role.subscriptionName || 'Unknown Scope',
        success: false,
        error: error.message
      });
    }
  }

  return {
    success: errors.length === 0,
    results: results,
    errors: errors,
    skipped: skipped
  };
}

function generateGuid() {
  return crypto.randomUUID();
}

// Function to activate PIM group memberships using PIM API
async function activateGroupMemberships(selectedGroups, durationHours, justification, graphToken, ticketInfo = {}) {
  if (!graphToken) {
    throw new Error('No Graph API token available. Please visit Microsoft Entra portal to sign in.');
  }

  if (!selectedGroups || selectedGroups.length === 0) {
    throw new Error('No groups selected for activation');
  }

  if (!justification || justification.trim() === '') {
    throw new Error('Justification is required');
  }

  if (durationHours <= 0) {
    throw new Error('Duration must be greater than 0 hours');
  }

  // Convert duration from hours to ISO 8601 duration format
  const isoDuration = `PT${Math.round(durationHours * 60)}M`;

  // Process each group activation request
  const results = [];
  const errors = [];
  const skipped = [];

  for (const group of selectedGroups) {
    try {
      // Validate required fields
      if (!group.groupId) {
        console.error('Group activation error: Missing groupId for group:', group);
        errors.push({
          group: group.groupName || 'Unknown Group',
          success: false,
          error: 'Missing group ID - please refresh and try again'
        });
        continue;
      }

      if (!group.principalId) {
        console.error('Group activation error: Missing principalId for group:', group);
        errors.push({
          group: group.groupName || group.groupId,
          success: false,
          error: 'Missing principal ID - please refresh and try again'
        });
        continue;
      }

      // Prepare request body for Graph API
      const requestBody = {
        "action": "selfActivate",
        "accessId": group.accessId || "member",
        "principalId": group.principalId,
        "groupId": group.groupId,
        "justification": justification,
        "scheduleInfo": {
          "startDateTime": new Date().toISOString(),
          "expiration": {
            "type": "afterDuration",
            "duration": isoDuration
          }
        }
      };

      // Add ticket info if provided
      if (ticketInfo.ticketNumber || ticketInfo.ticketSystem) {
        requestBody.ticketInfo = {
          "ticketNumber": ticketInfo.ticketNumber || "N/A",
          "ticketSystem": ticketInfo.ticketSystem || "Self-Service"
        };
      }

      // Send activation request to Graph API
      const response = await fetch(
        'https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests',
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${graphToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(requestBody)
        }
      );

      if (!response.ok) {
        let errorMessage = 'Unknown error';
        try {
          const errorData = await response.json();
          errorMessage = errorData.error?.message || errorData.message || JSON.stringify(errorData);
        } catch (e) {
          errorMessage = `HTTP ${response.status}: ${response.statusText}`;
        }

        // Check if group membership is already activated
        if (response.status === 400 && (errorMessage.includes('already exists') || errorMessage.includes('already active') || errorMessage.includes('RoleAssignmentExists') || errorMessage.includes('ActiveDuration'))) {
          skipped.push({
            group: group.groupName || group.groupId,
            reason: 'Already activated'
          });
          continue;
        }

        throw new Error(`API error (${response.status}): ${errorMessage}`);
      }

      const responseData = await response.json();
      results.push({
        group: group.groupName || group.groupId,
        success: true,
        requestId: responseData.id || responseData.requestId
      });

    } catch (error) {
      console.error('Group membership activation error:', error);
      errors.push({
        group: group.groupName || group.groupId,
        success: false,
        error: error.message
      });
    }
  }

  return {
    success: errors.length === 0,
    results: results,
    errors: errors,
    skipped: skipped
  };
}

// Function to activate roles (handles both directory and Azure resource roles)
async function activateAllRoles(selectedRoles, durationHours, justification, graphToken, azureManagementToken, pimToken, ticketInfo = {}) {
  const directoryRoles = selectedRoles.filter(role => role.roleType !== 'azureResource' && role.roleType !== 'group');
  const azureResourceRoles = selectedRoles.filter(role => role.roleType === 'azureResource');
  const groupMemberships = selectedRoles.filter(role => role.roleType === 'group');

  const allResults = {
    success: true,
    results: [],
    errors: [],
    skipped: []
  };

  // Activate directory roles
  if (directoryRoles.length > 0 && graphToken) {
    try {
      const directoryResult = await activatePimRoles(directoryRoles, durationHours, justification, graphToken, ticketInfo);
      allResults.results.push(...directoryResult.results);
      allResults.errors.push(...directoryResult.errors);
      if (directoryResult.skipped) allResults.skipped.push(...directoryResult.skipped);
    } catch (error) {
      allResults.errors.push({
        role: 'Directory Roles',
        success: false,
        error: error.message
      });
    }
  }

  // Activate Azure resource roles
  if (azureResourceRoles.length > 0 && azureManagementToken) {
    try {
      const azureResourceResult = await activateAzureResourceRoles(azureResourceRoles, durationHours, justification, azureManagementToken, ticketInfo);
      allResults.results.push(...azureResourceResult.results);
      allResults.errors.push(...azureResourceResult.errors);
      if (azureResourceResult.skipped) allResults.skipped.push(...azureResourceResult.skipped);
    } catch (error) {
      allResults.errors.push({
        role: 'Azure Resource Roles',
        success: false,
        error: error.message
      });
    }
  }

  // Activate group memberships using Graph API (same token as directory roles)
  if (groupMemberships.length > 0 && graphToken) {
    try {
      const groupResult = await activateGroupMemberships(groupMemberships, durationHours, justification, graphToken, ticketInfo);
      allResults.results.push(...groupResult.results);
      allResults.errors.push(...groupResult.errors);
      if (groupResult.skipped) allResults.skipped.push(...groupResult.skipped);
    } catch (error) {
      allResults.errors.push({
        group: 'PIM Group Memberships',
        success: false,
        error: error.message
      });
    }
  } else if (groupMemberships.length > 0 && !graphToken) {
    // No Graph token available for group activations
    allResults.errors.push({
      group: 'PIM Group Memberships',
      success: false,
      error: 'No Graph API token available. Please visit Microsoft Entra portal first.'
    });
  }

  allResults.success = allResults.errors.length === 0;
  return allResults;
}

// Export functions for use in popup.js
if (typeof module !== 'undefined') {
  module.exports = {
    activatePimRoles,
    activateAzureResourceRoles,
    activateAllRoles
  };
}
