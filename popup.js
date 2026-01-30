// Log immediately when script loads (before DOMContentLoaded)
console.log('[POPUP-SCRIPT] popup.js loaded at', new Date().toISOString());

document.addEventListener('DOMContentLoaded', function() {
  console.log('[POPUP] DOMContentLoaded event fired at ', new Date().toISOString());
  console.log('[POPUP] document.readyState:', document.readyState);
  console.log('[POPUP] body dimensions:', document.body.offsetWidth, 'x', document.body.offsetHeight);
  
  // Get DOM elements
  const statusMessage = document.getElementById('status-message');
  const refreshButton = document.getElementById('refresh-button');
  const tokenStatus = document.getElementById('token-status');
  const noTokenView = document.getElementById('no-token-view');
  const rolesContainer = document.getElementById('roles-container');
  const rolesList = document.getElementById('roles-list');
  const errorContainer = document.getElementById('error-container');
  const errorDetails = document.getElementById('error-details');
  const manualTokenInput = document.getElementById('manual-token');
  const saveTokenButton = document.getElementById('save-token-button');
  const clearTokenButton = document.getElementById('clear-token-button');
  const initialLoading = document.getElementById('initial-loading');
  
  // New elements for role activation
  const durationSlider = document.getElementById('duration-slider');
  const durationValue = document.getElementById('duration-value');
  const justificationText = document.getElementById('justification-text');
  const ticketSystem = document.getElementById('ticket-system');
  const ticketNumber = document.getElementById('ticket-number');
  
  // Add activation button element
  const activateButton = document.getElementById('activate-button');

  // Search and filter elements
  const roleSearch = document.getElementById('role-search');
  const clearSearchBtn = document.getElementById('clear-search');
  const searchResultsCount = document.getElementById('search-results-count');
  const filterChips = document.querySelectorAll('.filter-chip');

  // Tab navigation elements
  const tabButtons = document.querySelectorAll('.tab-button');
  const activeRolesContainer = document.getElementById('active-roles-container');
  const activeRolesList = document.getElementById('active-roles-list');

  // State for search and filter
  let currentSearchTerm = '';
  let currentFilter = 'all';
  let currentTab = 'eligible';
  let activeRolesInterval = null;

  // Initialize immediately - simple and straightforward
  console.log('[POPUP] Calling init() immediately');
  init();
  console.log('[POPUP] init() has been called');
  
  // Setup event listeners
  refreshButton.addEventListener('click', init);
  
  saveTokenButton.addEventListener('click', function() {
    const token = manualTokenInput.value.trim();
    if (token) {
      statusMessage.textContent = 'Saving token...';
      browser.runtime.sendMessage(
        { action: 'manualSetToken', token: token },
        function(response) {
          if (response && response.success) {
            manualTokenInput.value = '';
            init(); // Refresh the UI
          } else {
            showError(response?.error || 'Failed to save token');
          }
        }
      );
    }
  });
  
  clearTokenButton.addEventListener('click', function() {
    browser.runtime.sendMessage({ action: 'clearToken' }, function(response) {
      if (response && response.success) {
        init(); // Refresh the UI
      }
    });
  });
  
  // Open links in new tabs
  document.addEventListener('click', function(e) {
    if (e.target.tagName === 'A' && e.target.getAttribute('target') === '_blank') {
      e.preventDefault();
      browser.tabs.create({ url: e.target.href });
    }
  });
  
  // Slider event listener
  durationSlider.addEventListener('input', function() {
    durationValue.textContent = durationSlider.value;
  });

  // Search input event listener
  roleSearch.addEventListener('input', function(e) {
    currentSearchTerm = e.target.value.toLowerCase().trim();

    // Show/hide clear button
    if (currentSearchTerm) {
      clearSearchBtn.classList.remove('hidden');
    } else {
      clearSearchBtn.classList.add('hidden');
    }

    filterRoles();
  });

  // Clear search button
  clearSearchBtn.addEventListener('click', function() {
    roleSearch.value = '';
    currentSearchTerm = '';
    clearSearchBtn.classList.add('hidden');
    filterRoles();
    roleSearch.focus();
  });

  // Filter chip event listeners
  filterChips.forEach(chip => {
    chip.addEventListener('click', function() {
      // Remove active class from all chips
      filterChips.forEach(c => c.classList.remove('active'));

      // Add active class to clicked chip
      this.classList.add('active');

      // Update current filter
      currentFilter = this.dataset.filter;

      filterRoles();
    });
  });

  // Keyboard shortcut: Ctrl+F to focus search
  document.addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
      e.preventDefault();
      roleSearch.focus();
      roleSearch.select();
    }
  });

  // Tab switching event listeners
  tabButtons.forEach(button => {
    button.addEventListener('click', function() {
      const targetTab = this.dataset.tab;
      switchTab(targetTab);
    });
  });

  // Add activation button event listener
  activateButton.addEventListener('click', function() {
    const selectedRoles = getSelectedRoles();
    const duration = parseFloat(durationSlider.value);
    const justification = justificationText.value.trim();
    const ticketSystemValue = ticketSystem.value.trim();
    const ticketNumberValue = ticketNumber.value.trim();

    if (selectedRoles.length === 0) {
      showError('Please select at least one role to activate');
      return;
    }

    if (!justification) {
      showError('Please enter a justification');
      return;
    }

    if (duration <= 0) {
      showError('Please select a duration greater than 0');
      return;
    }

    statusMessage.textContent = 'Activating roles...';
    activateButton.disabled = true;

    // Get both tokens from storage
    browser.storage.local.get(['graphToken', 'azureManagementToken'], async function(data) {
      try {
        const encryptedGraphToken = data.graphToken;
        const encryptedAzureToken = data.azureManagementToken;

        // Check which types of roles are selected
        const hasDirectoryRoles = selectedRoles.some(r => r.roleType !== 'azureResource');
        const hasAzureResourceRoles = selectedRoles.some(r => r.roleType === 'azureResource');

        // Validate encrypted tokens exist
        if (hasDirectoryRoles && !encryptedGraphToken) {
          showError('No Graph API token found for Entra ID roles. Please visit Microsoft Entra portal first.');
          activateButton.disabled = false;
          return;
        }

        if (hasAzureResourceRoles && !encryptedAzureToken) {
          showError('No Azure Management token found for Azure resource roles. Please visit Azure Portal first.');
          activateButton.disabled = false;
          return;
        }

        // Decrypt tokens before using them
        let graphToken = null;
        let azureManagementToken = null;

        if (hasDirectoryRoles && encryptedGraphToken) {
          graphToken = await new Promise((resolve, reject) => {
            browser.runtime.sendMessage({
              action: 'decryptToken',
              encryptedToken: encryptedGraphToken
            }, (response) => {
              if (response && response.success) {
                resolve(response.token);
              } else {
                reject(new Error('Failed to decrypt Graph token'));
              }
            });
          });
        }

        if (hasAzureResourceRoles && encryptedAzureToken) {
          azureManagementToken = await new Promise((resolve, reject) => {
            browser.runtime.sendMessage({
              action: 'decryptToken',
              encryptedToken: encryptedAzureToken
            }, (response) => {
              if (response && response.success) {
                resolve(response.token);
              } else {
                reject(new Error('Failed to decrypt Azure Management token'));
              }
            });
          });
        }

        // Prepare ticket information
        const ticketInfo = {};
        if (ticketSystemValue) ticketInfo.ticketSystem = ticketSystemValue;
        if (ticketNumberValue) ticketInfo.ticketNumber = ticketNumberValue;

        // Call the unified activation function with decrypted tokens
        activateAllRoles(selectedRoles, duration, justification, graphToken, azureManagementToken, ticketInfo)
        .then(result => {
          if (result.success) {
            statusMessage.textContent = 'Roles activated successfully';

            // Build success message
            let successMessages = [];
            if (result.results.length > 0) {
              successMessages.push(`Successfully activated ${result.results.length} role(s)`);
            }
            if (result.skipped && result.skipped.length > 0) {
              successMessages.push(`${result.skipped.length} role(s) already active: ${result.skipped.map(s => s.role).join(', ')}`);
            }
            
            if (successMessages.length > 0) {
              alert(successMessages.join('\n'));
            }

            // Reset form
            justificationText.value = '';
            ticketSystem.value = '';
            ticketNumber.value = '';

            // Uncheck all checkboxes
            document.querySelectorAll('.role-checkbox:checked').forEach(cb => {
              cb.checked = false;
              // Also update storage
              const roleId = cb.id.replace('-checkbox', '');
              const saveObj = {};
              saveObj[`${roleId}-checked`] = false;
              browser.storage.local.set(saveObj);
            });
          } else {
            showError(`Failed to activate some roles: ${result.errors.map(e => `${e.role}${e.scope ? ` (${e.scope})` : ''}`).join(', ')}`);
          }

          activateButton.disabled = false;
        })
        .catch(error => {
          showError(`Activation error: ${error.message}`);
          activateButton.disabled = false;
        });
      } catch (error) {
        showError(`Token decryption error: ${error.message}`);
        activateButton.disabled = false;
      }
    });
  });
  
  // Main initialization function
  function init() {
    console.log('[POPUP] init() started');
    
    // Immediately show UI - synchronous, no callbacks
    initialLoading.classList.remove('hidden');
    noTokenView.classList.add('hidden');
    errorContainer.classList.add('hidden');
    rolesContainer.classList.add('hidden');
    activeRolesContainer.classList.add('hidden');
    statusMessage.textContent = 'Checking token';
    
    // Check token status
    browser.runtime.sendMessage({ action: 'getTokenStatus' }, function(response) {
      console.log('[POPUP] Token status received:', response);
      
      if (response && response.success) {
        updateTokenStatus(response.status);
        
        if (response.status.hasToken && !response.status.isExpired) {
          statusMessage.textContent = 'Loading roles';
          
          // Show appropriate container
          if (currentTab === 'active') {
            activeRolesContainer.classList.remove('hidden');
            activeRolesList.innerHTML = '<div class="loading-indicator"><div class="spinner"></div><p>Loading...</p></div>';
            loadActiveRoles();
          } else {
            rolesContainer.classList.remove('hidden');
            rolesList.innerHTML = '<div class="loading-indicator"><div class="spinner"></div><p>Loading...</p></div>';
            
            // Try cached first, then fresh
            browser.runtime.sendMessage({ action: 'getCachedRoles' }, (cachedResponse) => {
              if (cachedResponse && cachedResponse.success && cachedResponse.data) {
                console.log('[POPUP] Got cached roles, rendering');
                displayAllRoles(cachedResponse.data);
                initialLoading.classList.add('hidden');
                statusMessage.textContent = 'Roles loaded';
              } else {
                // No cache, load fresh
                browser.runtime.sendMessage({ action: 'getAllRoles' }, function(rolesResponse) {
                  if (rolesResponse && rolesResponse.success) {
                    console.log('[POPUP] Got fresh roles, rendering');
                    displayAllRoles(rolesResponse.data);
                    initialLoading.classList.add('hidden');
                    statusMessage.textContent = 'Roles loaded';
                  } else {
                    showError(rolesResponse?.error || 'Failed to load roles');
                  }
                });
              }
            });
          }
        } else {
          // No valid token
          console.log('[POPUP] No valid token - showing no-token view');
          initialLoading.classList.add('hidden');
          noTokenView.classList.remove('hidden');
          statusMessage.textContent = 'No valid token';
        }
      } else {
        console.log('[POPUP] Token status check failed');
        showError(response?.error || 'Failed to check token');
      }
    });
  }
  
  // Update token status display
  function updateTokenStatus(status) {
    // Clear existing content
    tokenStatus.textContent = '';
    
    if (status.hasToken) {
      if (status.isExpired) {
        const p1 = document.createElement('p');
        p1.className = 'warning';
        p1.textContent = `⚠️ Token expired (${status.tokenAge} min old)`;
        const p2 = document.createElement('p');
        p2.textContent = 'Please refresh your Microsoft session and try again.';
        tokenStatus.appendChild(p1);
        tokenStatus.appendChild(p2);
        tokenStatus.className = 'info-box warning';
      } else {
        const p = document.createElement('p');
        p.className = 'success';
        p.textContent = `✓ Valid token found (${status.tokenAge} min old)`;
        tokenStatus.appendChild(p);
        tokenStatus.className = 'info-box success';
      }
    } else {
      const p1 = document.createElement('p');
      p1.className = 'notice';
      p1.textContent = 'No token found';
      const p2 = document.createElement('p');
      p2.textContent = 'Sign in to a Microsoft service first.';
      tokenStatus.appendChild(p1);
      tokenStatus.appendChild(p2);
      tokenStatus.className = 'info-box notice';
    }
  }
  
  // Load and display PIM roles (both directory and Azure resource roles)
  function loadRoles() {
    // Don't modify DOM here - keep initialLoading visible until response
    statusMessage.textContent = 'Loading roles';
    
    browser.runtime.sendMessage({ action: 'getAllRoles' }, function(response) {
      if (response && response.success) {
        displayAllRoles(response.data);
        initialLoading.classList.add('hidden'); // Hide AFTER data is displayed
        statusMessage.textContent = 'Roles loaded';
        // DON'T clear keepalive - it needs to run to keep popup open
      } else {
        showError(response?.error || 'Failed to load roles');
        // DON'T clear keepalive - it needs to run to keep popup open
      }
    });
  }

  // Load roles in background without showing loading state (for cache refresh)
  function loadRolesInBackground() {
    browser.runtime.sendMessage({ action: 'getAllRoles' }, function(response) {
      if (response && response.success) {
        displayAllRoles(response.data);
        statusMessage.textContent = 'Roles updated';
      }
      // Silently fail if there's an error - we already have cached data displayed
    });
  }
  
  // Display all roles (both directory and Azure resource roles)
  function displayAllRoles(data) {
    rolesList.innerHTML = '';

    const directoryRoles = data.directoryRoles?.value || [];
    const azureResourceRoles = data.azureResourceRoles?.value || [];
    const errors = data.errors || [];

    // Display errors if any
    if (errors.length > 0) {
      const errorSection = document.createElement('div');
      errorSection.className = 'warning-section';
      errorSection.innerHTML = '<p><strong>⚠️ Some roles could not be loaded:</strong></p>';
      errors.forEach(err => {
        const errorMsg = document.createElement('p');
        errorMsg.className = 'error-message';
        errorMsg.textContent = `${err.type}: ${err.error}`;
        errorSection.appendChild(errorMsg);
      });
      rolesList.appendChild(errorSection);
    }

    // Check if we have any roles
    if (directoryRoles.length === 0 && azureResourceRoles.length === 0) {
      rolesList.innerHTML += '<p class="no-roles">No eligible PIM roles found for your account.</p>';
      rolesContainer.classList.remove('hidden');
      return;
    }

    // Display Directory Roles section
    if (directoryRoles.length > 0) {
      const directorySection = document.createElement('div');
      directorySection.className = 'role-section';
      const header = document.createElement('h3');
      header.className = 'role-section-title';
      header.textContent = '🔐 Entra ID Roles';
      directorySection.appendChild(header);

      directoryRoles.forEach(role => {
        const roleElement = createRoleElement(role, 'directory');
        directorySection.appendChild(roleElement);
      });

      rolesList.appendChild(directorySection);
    }

    // Display Azure Resource Roles section
    if (azureResourceRoles.length > 0) {
      const azureSection = document.createElement('div');
      azureSection.className = 'role-section';
      const header = document.createElement('h3');
      header.className = 'role-section-title';
      header.textContent = '☁️ Azure Resource Roles';
      azureSection.appendChild(header);

      azureResourceRoles.forEach(role => {
        const roleElement = createRoleElement(role, 'azureResource');
        azureSection.appendChild(roleElement);
      });

      rolesList.appendChild(azureSection);
    }

    rolesContainer.classList.remove('hidden');
  }

  // Helper function to create a role element
  function createRoleElement(role, roleType) {
    const roleElement = document.createElement('div');
    roleElement.className = 'role-item compact';

    // Store role data in dataset for later use in activation
    if (roleType === 'directory') {
      roleElement.dataset.roleDefinitionId = role.roleDefinitionId || '';
      roleElement.dataset.principalId = role.principalId || '';
      roleElement.dataset.directoryScopeId = role.directoryScopeId || '/';
      roleElement.dataset.roleType = 'directory';

      const roleName = role.roleName || role.roleDefinitionDisplayName ||
                        role.roleDefinitionId || 'Unknown Role';
      const roleId = role.roleDefinitionId ? `role-${role.roleDefinitionId.replace(/[-]/g, '')}` : `role-${Math.random().toString(36).substr(2, 9)}`;

      const container = document.createElement('div');
      container.className = 'role-flex-container';
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.id = `${roleId}-checkbox`;
      checkbox.className = 'role-checkbox';
      const titleDiv = document.createElement('div');
      titleDiv.className = 'role-title';
      titleDiv.textContent = roleName;
      container.appendChild(checkbox);
      container.appendChild(titleDiv);
      roleElement.appendChild(container);

      rolesList.appendChild(roleElement);

      // Load saved checkbox state
      browser.storage.local.get([`${roleId}-checked`], function(result) {
        if (result[`${roleId}-checked`]) {
          checkbox.checked = true;
        }
      });

      // Save checkbox state when changed
      checkbox.addEventListener('change', function() {
        const saveObj = {};
        saveObj[`${roleId}-checked`] = checkbox.checked;
        browser.storage.local.set(saveObj);
      });
    } else if (roleType === 'azureResource') {
      // Azure resource roles have different structure
      const roleDefinitionId = role.properties?.roleDefinitionId || role.roleDefinitionId || '';
      const principalId = role.properties?.principalId || role.principalId || '';
      const scope = role.properties?.scope || '';

      roleElement.dataset.roleDefinitionId = roleDefinitionId;
      roleElement.dataset.principalId = principalId;
      roleElement.dataset.scope = scope;
      roleElement.dataset.subscriptionId = role.subscriptionId || '';
      roleElement.dataset.roleType = 'azureResource';

      // Get role name from expandedProperties or fallback
      const roleName = role.properties?.expandedProperties?.roleDefinition?.displayName ||
                        role.roleName || 'Unknown Role';
      const subscriptionName = role.subscriptionName || 'Unknown Subscription';
      const scopeDisplay = extractScopeName(scope);

      const roleId = `azrole-${roleDefinitionId.replace(/[^a-zA-Z0-9]/g, '')}${Math.random().toString(36).substr(2, 5)}`;

      const container = document.createElement('div');
      container.className = 'role-flex-container';
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.id = `${roleId}-checkbox`;
      checkbox.className = 'role-checkbox';
      const detailsDiv = document.createElement('div');
      detailsDiv.className = 'role-details';
      const titleDiv = document.createElement('div');
      titleDiv.className = 'role-title';
      titleDiv.textContent = roleName;
      const scopeDiv = document.createElement('div');
      scopeDiv.className = 'role-scope';
      scopeDiv.textContent = subscriptionName + (scopeDisplay ? ` / ${scopeDisplay}` : '');
      detailsDiv.appendChild(titleDiv);
      detailsDiv.appendChild(scopeDiv);
      container.appendChild(checkbox);
      container.appendChild(detailsDiv);
      roleElement.appendChild(container);

      rolesList.appendChild(roleElement);

      // Load saved checkbox state
      browser.storage.local.get([`${roleId}-checked`], function(result) {
        if (result[`${roleId}-checked`]) {
          checkbox.checked = true;
        }
      });

      // Save checkbox state when changed
      checkbox.addEventListener('change', function() {
        const saveObj = {};
        saveObj[`${roleId}-checked`] = checkbox.checked;
        browser.storage.local.set(saveObj);
      });
    }

    return roleElement;
  }

  // Helper function to extract scope name from scope path
  function extractScopeName(scope) {
    if (!scope) return '';

    // Extract resource group name or resource name from scope
    const rgMatch = scope.match(/\/resourceGroups\/([^/]+)/i);
    if (rgMatch) {
      const resourceMatch = scope.match(/\/providers\/[^/]+\/[^/]+\/([^/]+)/i);
      if (resourceMatch) {
        return `${rgMatch[1]} > ${resourceMatch[1]}`;
      }
      return rgMatch[1];
    }

    return '';
  }

  // Legacy function kept for backwards compatibility (now calls displayAllRoles)
  function displayRoles(data) {
    displayAllRoles({
      directoryRoles: data,
      azureResourceRoles: { value: [] },
      errors: []
    });
  }
  
  // Show an error message
  function showError(message) {
    initialLoading.classList.add('hidden');
    errorDetails.textContent = message;
    errorContainer.classList.remove('hidden');
    statusMessage.textContent = 'Error';
    // DON'T clear keepalive - let it run until popup actually closes
  }
  
  // Helper function to safely escape HTML
  function escapeHTML(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
  
  // Function to gather selected roles with their data (handles both role types)
  function getSelectedRoles() {
    const selectedRoles = [];

    document.querySelectorAll('.role-checkbox:checked').forEach(checkbox => {
      const roleItem = checkbox.closest('.role-item');
      if (roleItem) {
        const roleType = roleItem.dataset.roleType;
        const roleTitleElement = roleItem.querySelector('.role-title');

        if (roleType === 'azureResource') {
          // Azure resource role
          selectedRoles.push({
            roleType: 'azureResource',
            roleDefinitionId: roleItem.dataset.roleDefinitionId,
            principalId: roleItem.dataset.principalId,
            scope: roleItem.dataset.scope,
            subscriptionId: roleItem.dataset.subscriptionId,
            roleName: roleTitleElement ? roleTitleElement.textContent : 'Unknown Role',
            properties: {
              roleDefinitionId: roleItem.dataset.roleDefinitionId,
              principalId: roleItem.dataset.principalId,
              scope: roleItem.dataset.scope
            }
          });
        } else {
          // Directory role (default)
          selectedRoles.push({
            roleType: 'directory',
            roleDefinitionId: roleItem.dataset.roleDefinitionId,
            principalId: roleItem.dataset.principalId,
            directoryScopeId: roleItem.dataset.directoryScopeId || "/",
            roleName: roleTitleElement ? roleTitleElement.textContent : 'Unknown Role'
          });
        }
      }
    });

    return selectedRoles;
  }

  // Filter roles based on search term and filter type
  function filterRoles() {
    const allRoleItems = document.querySelectorAll('.role-item');
    const allRoleSections = document.querySelectorAll('.role-section');
    let visibleCount = 0;
    let totalCount = allRoleItems.length;

    allRoleItems.forEach(roleItem => {
      const roleType = roleItem.dataset.roleType;
      const roleTitleElement = roleItem.querySelector('.role-title');
      const roleScopeElement = roleItem.querySelector('.role-scope');

      const roleName = roleTitleElement ? roleTitleElement.textContent.toLowerCase() : '';
      const roleScope = roleScopeElement ? roleScopeElement.textContent.toLowerCase() : '';

      // Check filter type
      let matchesFilter = true;
      if (currentFilter === 'directory') {
        matchesFilter = roleType === 'directory';
      } else if (currentFilter === 'azureResource') {
        matchesFilter = roleType === 'azureResource';
      }

      // Check search term
      let matchesSearch = true;
      if (currentSearchTerm) {
        matchesSearch = roleName.includes(currentSearchTerm) || roleScope.includes(currentSearchTerm);
      }

      // Show/hide based on both criteria
      const shouldShow = matchesFilter && matchesSearch;
      roleItem.style.display = shouldShow ? '' : 'none';

      if (shouldShow) {
        visibleCount++;
      }
    });

    // Show/hide role section headings based on filter
    allRoleSections.forEach(section => {
      const sectionTitle = section.querySelector('.role-section-title');
      if (sectionTitle) {
        const titleText = sectionTitle.textContent;
        
        // Hide Entra ID section when Azure Resource filter is active
        if (currentFilter === 'azureResource' && titleText.includes('Entra ID')) {
          section.style.display = 'none';
        }
        // Hide Azure Resource section when Entra ID filter is active
        else if (currentFilter === 'directory' && titleText.includes('Azure Resource')) {
          section.style.display = 'none';
        }
        // Show all sections when 'all' filter is active
        else if (currentFilter === 'all') {
          section.style.display = '';
        }
        // For other cases, check if section has any visible roles
        else {
          const visibleRolesInSection = section.querySelectorAll('.role-item:not([style*="display: none"])');
          section.style.display = visibleRolesInSection.length > 0 ? '' : 'none';
        }
      }
    });

    // Update results count
    updateSearchResultsCount(visibleCount, totalCount);

    // Show/hide "no results" message
    updateNoResultsMessage(visibleCount);
  }

  // Update search results count display
  function updateSearchResultsCount(visible, total) {
    if (currentSearchTerm || currentFilter !== 'all') {
      searchResultsCount.textContent = `Showing ${visible} of ${total} roles`;
      searchResultsCount.classList.remove('hidden');
    } else {
      searchResultsCount.classList.add('hidden');
    }
  }

  // Show "no results" message if all roles are hidden
  function updateNoResultsMessage(visibleCount) {
    // Remove existing no-results message if any
    const existingMessage = rolesList.querySelector('.no-results-message');
    if (existingMessage) {
      existingMessage.remove();
    }

    // Add no-results message if needed
    if (visibleCount === 0 && (currentSearchTerm || currentFilter !== 'all')) {
      const noResultsDiv = document.createElement('div');
      noResultsDiv.className = 'no-results-message';
      noResultsDiv.innerHTML = `
        <div class="icon">🔍</div>
        <p><strong>No roles found</strong></p>
        <p>Try adjusting your search or filter criteria</p>
      `;
      rolesList.appendChild(noResultsDiv);
    }
  }

  // Switch between tabs
  function switchTab(tabName) {
    currentTab = tabName;

    // Update tab button active states
    tabButtons.forEach(btn => {
      if (btn.dataset.tab === tabName) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    // Show/hide appropriate containers
    if (tabName === 'eligible') {
      rolesContainer.classList.remove('hidden');
      activeRolesContainer.classList.add('hidden');

      // Stop active roles interval if running
      if (activeRolesInterval) {
        clearInterval(activeRolesInterval);
        activeRolesInterval = null;
      }
    } else if (tabName === 'active') {
      rolesContainer.classList.add('hidden');
      activeRolesContainer.classList.remove('hidden');

      // Show loading indicator before loading active roles
      activeRolesList.innerHTML = `
        <div class="loading-indicator">
          <div class="spinner"></div>
          <p>Loading active roles...</p>
        </div>
      `;
      statusMessage.textContent = 'Loading active roles';

      // Load and display active roles
      loadActiveRoles();

      // Set up interval to refresh active roles every 30 seconds
      if (activeRolesInterval) {
        clearInterval(activeRolesInterval);
      }
      activeRolesInterval = setInterval(() => {
        // Show loading indicator before refresh
        activeRolesList.innerHTML = `
          <div class="loading-indicator">
            <div class="spinner"></div>
            <p>Refreshing active roles...</p>
          </div>
        `;
        statusMessage.textContent = 'Refreshing active roles';
        loadActiveRoles();
      }, 30000);
    }
  }

  function loadActiveRoles() {
    // Don't modify DOM here - keep initialLoading visible until response
    statusMessage.textContent = 'Loading active roles';
    
    browser.runtime.sendMessage({ action: 'getActiveRoles' }, function(response) {
      if (response && response.success) {
        displayActiveRoles(response.data);
        initialLoading.classList.add('hidden'); // Hide AFTER data is displayed
        statusMessage.textContent = 'Active roles loaded';
        // DON'T clear keepalive - it needs to run to keep popup open
      } else {
        showError(response?.error || 'Failed to load active roles');
        // DON'T clear keepalive - it needs to run to keep popup open
      }
    });
  }

  // Display active roles with countdown timers
  function displayActiveRoles(data) {
    activeRolesList.innerHTML = '';

    const activeDirectoryRoles = data.activeDirectoryRoles?.value || [];
    const activeAzureResourceRoles = data.activeAzureResourceRoles?.value || [];
    const errors = data.errors || [];

    // Debug logging
    console.log('Active Directory Roles count:', activeDirectoryRoles.length);
    console.log('Active Azure Resource Roles count:', activeAzureResourceRoles.length);
    console.log('Active Azure Resource Roles data:', activeAzureResourceRoles);
    console.log('Errors:', errors);

    // Display errors if any
    if (errors.length > 0) {
      const errorSection = document.createElement('div');
      errorSection.className = 'warning-section';
      errorSection.innerHTML = '<p><strong>⚠️ Some active roles could not be loaded:</strong></p>';
      errors.forEach(err => {
        const errorMsg = document.createElement('p');
        errorMsg.className = 'error-message';
        errorMsg.textContent = `${err.type}: ${err.error}`;
        errorSection.appendChild(errorMsg);
      });
      activeRolesList.appendChild(errorSection);
    }

    // Check if we have any active roles
    if (activeDirectoryRoles.length === 0 && activeAzureResourceRoles.length === 0) {
      const noActiveDiv = document.createElement('div');
      noActiveDiv.className = 'no-active-roles';
      const iconDiv = document.createElement('div');
      iconDiv.className = 'icon';
      iconDiv.textContent = '⏸️';
      const p1 = document.createElement('p');
      const strong = document.createElement('strong');
      strong.textContent = 'No active roles';
      p1.appendChild(strong);
      const p2 = document.createElement('p');
      p2.textContent = 'Switch to "Eligible Roles" tab to activate roles';
      noActiveDiv.appendChild(iconDiv);
      noActiveDiv.appendChild(p1);
      noActiveDiv.appendChild(p2);
      activeRolesList.appendChild(noActiveDiv);
      return;
    }

    // Display Directory Active Roles section
    if (activeDirectoryRoles.length > 0) {
      const directorySection = document.createElement('div');
      directorySection.className = 'role-section';
      const header = document.createElement('h3');
      header.className = 'role-section-title';
      header.textContent = '🔐 Active Entra ID Roles';
      directorySection.appendChild(header);

      activeDirectoryRoles.forEach(role => {
        const roleCard = createActiveRoleCard(role, 'directory');
        directorySection.appendChild(roleCard);
      });

      activeRolesList.appendChild(directorySection);
    }

    // Display Azure Resource Active Roles section
    if (activeAzureResourceRoles.length > 0) {
      const azureSection = document.createElement('div');
      azureSection.className = 'role-section';
      const header = document.createElement('h3');
      header.className = 'role-section-title';
      header.textContent = '☁️ Active Azure Resource Roles';
      azureSection.appendChild(header);

      activeAzureResourceRoles.forEach(role => {
        const roleCard = createActiveRoleCard(role, 'azureResource');
        azureSection.appendChild(roleCard);
      });

      activeRolesList.appendChild(azureSection);
    }
  }

  // Create an active role card with countdown timer
  function createActiveRoleCard(role, roleType) {
    const card = document.createElement('div');
    card.className = 'active-role-card';

    let roleName, scopeInfo, endDateTime;

    if (roleType === 'directory') {
      roleName = role.roleName || role.roleDefinition?.displayName || 'Unknown Role';
      scopeInfo = 'Directory scope';
      endDateTime = role.endDateTime;
    } else if (roleType === 'azureResource') {
      roleName = role.properties?.expandedProperties?.roleDefinition?.displayName || 'Unknown Role';
      const subscriptionName = role.subscriptionName || 'Unknown Subscription';
      const scopeDisplay = extractScopeName(role.properties?.scope || '');
      scopeInfo = `${subscriptionName}${scopeDisplay ? ` / ${scopeDisplay}` : ''}`;
      endDateTime = role.properties?.endDateTime;
    }

    if (!endDateTime) {
      // No expiration time, just show basic info
      const header = document.createElement('div');
      header.className = 'active-role-header';
      const nameDiv = document.createElement('div');
      nameDiv.className = 'active-role-name';
      nameDiv.textContent = roleName;
      const badge = document.createElement('span');
      badge.className = 'active-role-badge active';
      badge.textContent = 'Active';
      header.appendChild(nameDiv);
      header.appendChild(badge);
      
      const infoDiv = document.createElement('div');
      infoDiv.className = 'active-role-info';
      infoDiv.textContent = scopeInfo;
      
      const actionsDiv = document.createElement('div');
      actionsDiv.className = 'active-role-actions';
      const deactivateBtn = document.createElement('button');
      deactivateBtn.className = 'deactivate-btn';
      deactivateBtn.title = 'Deactivate this role';
      deactivateBtn.textContent = 'Deactivate';
      actionsDiv.appendChild(deactivateBtn);
      
      card.appendChild(header);
      card.appendChild(infoDiv);
      card.appendChild(actionsDiv);
      
      // Add deactivate button click handler
      deactivateBtn.addEventListener('click', () => {
        deactivateRole(role, roleType);
      });
      
      return card;
    }

    // Calculate time remaining
    const endTime = new Date(endDateTime).getTime();
    const now = Date.now();
    const timeRemaining = endTime - now;

    // Determine if expiring soon (less than 15 minutes)
    const isExpiringSoon = timeRemaining < 15 * 60 * 1000;

    if (isExpiringSoon) {
      card.classList.add('expiring-soon');
    }

    // Create unique ID for this card
    const cardId = `active-role-${Math.random().toString(36).substr(2, 9)}`;
    card.id = cardId;

    const header = document.createElement('div');
    header.className = 'active-role-header';
    const nameDiv = document.createElement('div');
    nameDiv.className = 'active-role-name';
    nameDiv.textContent = roleName;
    const badge = document.createElement('span');
    badge.className = `active-role-badge ${isExpiringSoon ? 'expiring' : 'active'}`;
    badge.textContent = isExpiringSoon ? '⚠️ Expiring' : 'Active';
    header.appendChild(nameDiv);
    header.appendChild(badge);
    
    const infoDiv = document.createElement('div');
    infoDiv.className = 'active-role-info';
    infoDiv.textContent = scopeInfo;
    
    const timerDiv = document.createElement('div');
    timerDiv.className = 'active-role-timer';
    const progressBar = document.createElement('div');
    progressBar.className = 'timer-progress-bar';
    const progressFill = document.createElement('div');
    progressFill.className = `timer-progress-fill ${isExpiringSoon ? 'expiring-soon' : ''}`;
    progressFill.id = `${cardId}-progress`;
    const timerText = document.createElement('div');
    timerText.className = `timer-text-overlay ${isExpiringSoon ? 'expiring-soon' : ''}`;
    timerText.id = `${cardId}-timer`;
    progressBar.appendChild(progressFill);
    progressBar.appendChild(timerText);
    timerDiv.appendChild(progressBar);
    
    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'active-role-actions';
    const deactivateBtn = document.createElement('button');
    deactivateBtn.className = 'deactivate-btn';
    deactivateBtn.title = 'Deactivate this role';
    deactivateBtn.textContent = 'Deactivate';
    actionsDiv.appendChild(deactivateBtn);
    
    card.appendChild(header);
    card.appendChild(infoDiv);
    card.appendChild(timerDiv);
    card.appendChild(actionsDiv);

    // Start countdown timer after a brief delay to ensure DOM is ready
    setTimeout(() => {
      updateCountdown(cardId, endTime);
    }, 10);

    // Add deactivate button click handler
    deactivateBtn.addEventListener('click', () => {
      deactivateRole(role, roleType);
    });

    return card;
  }

  // Deactivate a role
  async function deactivateRole(role, roleType) {
    const roleName = roleType === 'directory' 
      ? (role.roleName || role.roleDefinition?.displayName || 'this role')
      : (role.properties?.expandedProperties?.roleDefinition?.displayName || 'this role');
    
    if (!confirm(`Are you sure you want to deactivate "${roleName}"?`)) {
      return;
    }

    // Show loading state
    statusMessage.textContent = `Deactivating ${roleName}...`;

    try {
      if (roleType === 'directory') {
        await deactivateDirectoryRole(role);
      } else if (roleType === 'azureResource') {
        await deactivateAzureResourceRole(role);
      }

      statusMessage.textContent = `Successfully deactivated ${roleName}`;
      
      // Reload active roles after a delay to allow API to update
      setTimeout(() => {
        // Show loading indicator before reloading active roles
        activeRolesList.innerHTML = `
          <div class="loading-indicator">
            <div class="spinner"></div>
            <p>Reloading active roles...</p>
          </div>
        `;
        statusMessage.textContent = 'Reloading active roles';
        loadActiveRoles();
      }, 2000);
    } catch (error) {
      console.error('Deactivation error:', error);
      showError(`Failed to deactivate ${roleName}: ${error.message}`);
    }
  }

  // Deactivate a directory role
  async function deactivateDirectoryRole(role) {
    const response = await browser.runtime.sendMessage({
      action: 'getTokens'
    });

    if (!response || !response.success || !response.tokens.graphToken) {
      throw new Error('No Graph API token available');
    }

    const token = response.tokens.graphToken;
    const principalId = role.principalId;
    const roleDefinitionId = role.roleDefinitionId;
    const directoryScopeId = role.directoryScopeId || "/";

    const requestBody = {
      "action": "selfDeactivate",
      "principalId": principalId,
      "roleDefinitionId": roleDefinitionId,
      "directoryScopeId": directoryScopeId
    };

    const apiResponse = await fetch(
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

    if (!apiResponse.ok) {
      const errorData = await apiResponse.json();
      const errorMessage = errorData.error?.message || `HTTP ${apiResponse.status}`;
      
      // Check if role is already deactivated
      if (apiResponse.status === 400 && errorMessage.includes('does not exist')) {
        // Role was already deactivated - this is fine, just refresh the list
        console.log('Role assignment already deactivated');
        return { alreadyDeactivated: true };
      }
      
      throw new Error(errorMessage);
    }

    return await apiResponse.json();
  }

  // Deactivate an Azure resource role
  async function deactivateAzureResourceRole(role) {
    const response = await browser.runtime.sendMessage({
      action: 'getTokens'
    });

    if (!response || !response.success || !response.tokens.azureManagementToken) {
      throw new Error('No Azure Management token available');
    }

    const token = response.tokens.azureManagementToken;
    const requestId = generateGuid();
    const scope = role.properties?.scope || `/subscriptions/${role.subscriptionId}`;
    const principalId = role.properties?.principalId || role.principalId;
    const roleDefinitionId = role.properties?.roleDefinitionId || role.roleDefinitionId;

    const requestBody = {
      "properties": {
        "principalId": principalId,
        "roleDefinitionId": roleDefinitionId,
        "requestType": "SelfDeactivate"
      }
    };

    const apiResponse = await fetch(
      `https://management.azure.com${scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/${requestId}?api-version=2020-10-01`,
      {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      }
    );

    if (!apiResponse.ok) {
      const errorData = await apiResponse.json();
      const errorMessage = errorData.error?.message || `HTTP ${apiResponse.status}`;
      
      // Check if role is already deactivated
      if (apiResponse.status === 400 && errorMessage.includes('does not exist')) {
        // Role was already deactivated - this is fine, just refresh the list
        console.log('Azure resource role assignment already deactivated');
        return { alreadyDeactivated: true };
      }
      
      throw new Error(errorMessage);
    }

    return await apiResponse.json();
  }

  // Helper function to generate a GUID
  function generateGuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  // Update countdown timer for a role card
  function updateCountdown(cardId, endTime) {
    const timerElement = document.getElementById(`${cardId}-timer`);
    const progressElement = document.getElementById(`${cardId}-progress`);

    if (!timerElement || !progressElement) return;

    const updateTimer = () => {
      const now = Date.now();
      const timeRemaining = endTime - now;

      if (timeRemaining <= 0) {
        timerElement.textContent = 'Expired';
        progressElement.style.width = '0%';
        return;
      }

      // Calculate hours, minutes, seconds
      const hours = Math.floor(timeRemaining / (1000 * 60 * 60));
      const minutes = Math.floor((timeRemaining % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((timeRemaining % (1000 * 60)) / 1000);

      // Format time string
      let timeString = '';
      if (hours > 0) {
        timeString = `${hours}h ${minutes}m`;
      } else if (minutes > 0) {
        timeString = `${minutes}m ${seconds}s`;
      } else {
        timeString = `${seconds}s`;
      }

      timerElement.textContent = timeString;

      // Update progress bar (assume 8 hour max duration for calculation)
      const maxDuration = 8 * 60 * 60 * 1000; // 8 hours in milliseconds
      const percentRemaining = Math.max(0, Math.min(100, (timeRemaining / maxDuration) * 100));
      progressElement.style.width = `${percentRemaining}%`;
    };

    // Initial update
    updateTimer();

    // Update every second
    const interval = setInterval(() => {
      updateTimer();

      // Stop if timer expired or card no longer exists
      if (!document.getElementById(cardId)) {
        clearInterval(interval);
      }
    }, 1000);
  }
  
  console.log('[POPUP] DOMContentLoaded event handler completed');
});

// Also log window load event
window.addEventListener('load', function() {
  console.log('[POPUP] window load event fired');
});

// Log any errors
window.addEventListener('error', function(e) {
  console.error('[POPUP] Window error:', e.message, e.filename, e.lineno, e.colno);
});

// Force cleanup on unload
window.addEventListener('unload', function() {
  console.log('[POPUP] Unload event - cleaning up');
  // Clear any intervals
  if (typeof activeRolesInterval !== 'undefined' && activeRolesInterval) {
    clearInterval(activeRolesInterval);
  }
});

// Log when popup becomes visible/hidden
document.addEventListener('visibilitychange', function() {
  console.log('[POPUP] Visibility changed:', document.visibilityState);
});
