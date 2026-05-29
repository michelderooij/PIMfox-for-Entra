document.addEventListener('DOMContentLoaded', function() {
  // Get DOM elements
  const statusMessage = document.getElementById('status-message');
  const refreshButton = document.getElementById('refresh-button');
  const darkModeToggle = document.getElementById('dark-mode-toggle');
  const tokenStatus = document.getElementById('token-status');
  const noTokenView = document.getElementById('no-token-view');
  const rolesContainer = document.getElementById('roles-container');
  const rolesList = document.getElementById('roles-list');
  const errorContainer = document.getElementById('error-container');
  const errorDetails = document.getElementById('error-details');
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
  const filterChips = document.querySelectorAll('.filter-chip[data-filter]');
  const statusFilterChips = document.querySelectorAll('.filter-chip[data-status-filter]');

  // State for search and filter
  let currentSearchTerm = '';
  let currentFilter = 'all';
  let currentStatusFilter = 'all';
  let activeTimerIntervals = [];
  let refreshInterval = null;
  let tokenPollInterval = null;
  let currentUpn = null;
  let currentCookieStoreId = 'firefox-default';

  // Initialize immediately - simple and straightforward
  init();

  // Dark mode: restore saved preference and wire up toggle
  browser.storage.local.get('darkMode', function(result) {
    // Use stored preference if set; otherwise fall back to browser/OS preference
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const useDark = (result.darkMode !== undefined) ? result.darkMode : prefersDark;
    if (useDark) {
      document.body.classList.add('dark-mode');
      darkModeToggle.textContent = '☀️';
      darkModeToggle.title = 'Switch to light mode';
    }
  });

  darkModeToggle.addEventListener('click', function() {
    const isDark = document.body.classList.toggle('dark-mode');
    darkModeToggle.textContent = isDark ? '☀️' : '🌙';
    darkModeToggle.title = isDark ? 'Switch to light mode' : 'Toggle dark mode';
    browser.storage.local.set({ darkMode: isDark });
  });

  // Setup event listeners
  refreshButton.addEventListener('click', () => init(true));
  
  clearTokenButton.addEventListener('click', function() {
    browser.runtime.sendMessage({ action: 'clearToken', cookieStoreId: currentCookieStoreId }, function(response) {
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

  // Update the slider maximum based on the lowest policy max of all checked roles
  function updateSliderMax() {
    const checkedBoxes = document.querySelectorAll('.role-checkbox:checked');
    const durationAdjustInfo = document.getElementById('duration-adjust-info');

    let effectiveMax;
    if (checkedBoxes.length === 0) {
      effectiveMax = 8;
    } else {
      const maxDurations = Array.from(checkedBoxes).map(cb => {
        const roleItem = cb.closest('.role-item');
        return parseFloat(roleItem?.dataset.maxDuration || 8);
      });
      effectiveMax = Math.min(Math.min(...maxDurations), 8);
    }

    const currentMax = parseFloat(durationSlider.max);
    if (Math.abs(effectiveMax - currentMax) > 0.001) {
      durationSlider.max = effectiveMax;
      if (parseFloat(durationSlider.value) > effectiveMax) {
        durationSlider.value = effectiveMax;
        durationValue.textContent = effectiveMax % 1 === 0 ? String(effectiveMax) : effectiveMax.toFixed(1);
      }
    }

    if (durationAdjustInfo) {
      if (checkedBoxes.length > 0 && effectiveMax < 8) {
        const label = effectiveMax % 1 === 0 ? String(effectiveMax) : effectiveMax.toFixed(1);
        durationAdjustInfo.textContent = `\u2139\uFE0F Maximum duration adjusted to ${label}h based on current selection of roles, PIM groups and Azure resources.`;
        durationAdjustInfo.classList.remove('hidden');
      } else {
        durationAdjustInfo.classList.add('hidden');
      }
    }
  }

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
      // Remove active class from all type filter chips
      filterChips.forEach(c => c.classList.remove('active'));

      // Add active class to clicked chip
      this.classList.add('active');

      // Update current filter
      currentFilter = this.dataset.filter;

      browser.runtime.sendMessage({ action: 'invalidateRolesCache', cookieStoreId: currentCookieStoreId });
      filterRoles();
    });
  });

  // Status filter chip event listeners
  statusFilterChips.forEach(chip => {
    chip.addEventListener('click', function() {
      // Remove active class from all status filter chips
      statusFilterChips.forEach(c => c.classList.remove('active'));

      // Add active class to clicked chip
      this.classList.add('active');

      // Update current status filter
      currentStatusFilter = this.dataset.statusFilter;

      browser.runtime.sendMessage({ action: 'invalidateRolesCache', cookieStoreId: currentCookieStoreId });
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

    // Get all tokens from background service (container-scoped)
    browser.runtime.sendMessage({ action: 'getTokens', cookieStoreId: currentCookieStoreId }, async function(response) {
      try {
        if (!response || !response.success) {
          showError('Failed to retrieve tokens. Please refresh your Microsoft session.');
          activateButton.disabled = false;
          return;
        }

        const { graphToken, azureManagementToken, pimToken } = response.tokens;

        // Check which types of roles are selected
        const hasDirectoryRoles = selectedRoles.some(r => r.roleType !== 'azureResource' && r.roleType !== 'group');
        const hasAzureResourceRoles = selectedRoles.some(r => r.roleType === 'azureResource');
        const hasGroupMemberships = selectedRoles.some(r => r.roleType === 'group');

        // Validate tokens exist for selected role types
        if (hasDirectoryRoles && !graphToken) {
          showError('No Graph API token found for Entra ID roles. Please visit Microsoft Entra portal first.');
          activateButton.disabled = false;
          return;
        }

        if (hasAzureResourceRoles && !azureManagementToken) {
          showError('No Azure Management token found for Azure resource roles. Please visit Azure Portal first.');
          activateButton.disabled = false;
          return;
        }

        if (hasGroupMemberships && !graphToken) {
          showError('No Graph API token found for group memberships. Please visit Microsoft Entra portal first.');
          activateButton.disabled = false;
          return;
        }

        // Prepare ticket information
        const ticketInfo = {};
        if (ticketSystemValue) ticketInfo.ticketSystem = ticketSystemValue;
        if (ticketNumberValue) ticketInfo.ticketNumber = ticketNumberValue;

        // Show activation spinner
        const activationStatus = document.getElementById('activation-status');
        const activationSpinner = document.getElementById('activation-spinner');
        const activationMessage = document.getElementById('activation-message');
        
        activationStatus.classList.remove('hidden');
        activationSpinner.classList.remove('hidden');
        activationMessage.classList.add('hidden');
        
        // Call the unified activation function with decrypted tokens
        activateAllRoles(selectedRoles, duration, justification, graphToken, azureManagementToken, pimToken, ticketInfo)
        .then(result => {
          // Hide spinner
          activationSpinner.classList.add('hidden');
          
          if (result.success) {
            statusMessage.textContent = 'Roles activated successfully';

            // Build success message
            let successMessages = [];
            if (result.results.length > 0) {
              const roleCount = result.results.filter(r => r.role).length;
              const groupCount = result.results.filter(r => r.group).length;
              
              if (roleCount > 0) successMessages.push(`Successfully activated ${roleCount} role(s)`);
              if (groupCount > 0) successMessages.push(`Successfully activated ${groupCount} group membership(s)`);
            }
            if (result.skipped && result.skipped.length > 0) {
              const skippedRoles = result.skipped.filter(s => s.role).map(s => s.role);
              const skippedGroups = result.skipped.filter(s => s.group).map(s => s.group);
              
              if (skippedRoles.length > 0) {
                successMessages.push(`${skippedRoles.length} role(s) already active`);
              }
              if (skippedGroups.length > 0) {
                successMessages.push(`${skippedGroups.length} group(s) already active`);
              }
            }
            
            // Show success message inline
            if (successMessages.length > 0) {
              activationMessage.textContent = successMessages.join(' • ');
              activationMessage.className = 'success';
              activationMessage.classList.remove('hidden');
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

            // Refresh roles after a delay to allow API to update
            setTimeout(() => {
              statusMessage.textContent = 'Reloading roles...';
              loadAllRolesUnified(false);
            }, 2000);
          } else {
            const errorRoles = result.errors.filter(e => e.role).map(e => `${e.role}${e.scope ? ` (${e.scope})` : ''}`);
            const errorGroups = result.errors.filter(e => e.group).map(e => e.group);
            const allErrors = [...errorRoles, ...errorGroups];
            
            // Show error message inline
            activationMessage.textContent = `Failed to activate: ${allErrors.join(', ')}`;
            activationMessage.className = 'error';
            activationMessage.classList.remove('hidden');
          }

          activateButton.disabled = false;
        })
        .catch(error => {
          // Hide spinner and show error inline
          activationSpinner.classList.add('hidden');
          activationMessage.textContent = `Activation error: ${error.message}`;
          activationMessage.className = 'error';
          activationMessage.classList.remove('hidden');
          activateButton.disabled = false;
        });
      } catch (error) {
        showError(`Activation error: ${error.message}`);
        activateButton.disabled = false;
      }
    });
  });
  
  // Main initialization function
  async function init(forceRefresh = false) {
    // Resolve current Firefox container before any messaging
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    currentCookieStoreId = tabs[0]?.cookieStoreId || 'firefox-default';

    // Clear any existing timer intervals
    activeTimerIntervals.forEach(clearInterval);
    activeTimerIntervals = [];
    if (refreshInterval) {
      clearInterval(refreshInterval);
      refreshInterval = null;
    }
    if (tokenPollInterval) {
      clearInterval(tokenPollInterval);
      tokenPollInterval = null;
    }
    
    // Immediately show UI - synchronous, no callbacks
    initialLoading.classList.remove('hidden');
    noTokenView.classList.add('hidden');
    errorContainer.classList.add('hidden');
    rolesContainer.classList.add('hidden');
    statusMessage.textContent = 'Checking token';
    
    // Check token status
    browser.runtime.sendMessage({ action: 'getTokenStatus', cookieStoreId: currentCookieStoreId }, function(response) {
      if (response && response.success) {
        updateTokenStatus(response.status);
        currentUpn = response.status.upn || null;
        
        if (response.status.hasToken && !response.status.isExpired) {
          statusMessage.textContent = `Loading roles${currentUpn ? ` for ${currentUpn}` : ''}`;
          
          rolesContainer.classList.remove('hidden');
          rolesList.innerHTML = '<div class="loading-indicator"><div class="spinner"></div><p>Loading...</p></div>';
          
          // Load both eligible and active roles
          loadAllRolesUnified(false, forceRefresh);
          
          // Set up auto-refresh every 30 seconds
          refreshInterval = setInterval(() => {
            loadAllRolesUnified(true); // silent refresh, serves from cache
          }, 30000);
        } else {
          // No valid token — start polling until the portal makes an API call
          initialLoading.classList.add('hidden');
          noTokenView.classList.remove('hidden');
          statusMessage.textContent = 'Waiting for portal activity...';
          tokenPollInterval = setInterval(() => {
            browser.runtime.sendMessage({ action: 'getTokenStatus', cookieStoreId: currentCookieStoreId }, (pollResponse) => {
              if (pollResponse?.success && pollResponse.status.hasToken && !pollResponse.status.isExpired) {
                clearInterval(tokenPollInterval);
                tokenPollInterval = null;
                init();
              }
            });
          }, 5000);
          setTimeout(() => {
            if (tokenPollInterval) {
              clearInterval(tokenPollInterval);
              tokenPollInterval = null;
              statusMessage.textContent = 'No valid token';
            }
          }, 120000);
        }
      } else {
        showError(response?.error || 'Failed to check token');
      }
    });
  }
  
  // Load both eligible and active roles into unified view
  function loadAllRolesUnified(silentRefresh = false, forceRefresh = false) {
    if (!silentRefresh) {
      statusMessage.textContent = currentUpn ? `Loading roles for ${currentUpn}` : 'Loading roles...';
    }
    
    // Fetch both eligible and active roles in parallel
    Promise.all([
      new Promise((resolve) => {
        browser.runtime.sendMessage({ action: 'getAllRoles', forceRefresh, cookieStoreId: currentCookieStoreId }, (response) => {
          resolve(response?.success ? response.data : null);
        });
      }),
      new Promise((resolve) => {
        browser.runtime.sendMessage({ action: 'getActiveRoles', forceRefresh, cookieStoreId: currentCookieStoreId }, (response) => {
          resolve(response?.success ? response.data : null);
        });
      })
    ]).then(([eligibleData, activeData]) => {
      displayUnifiedRoles(eligibleData, activeData);
      initialLoading.classList.add('hidden');
      statusMessage.textContent = currentUpn ? `Roles loaded for ${currentUpn}` : 'Roles loaded';
    }).catch((error) => {
      showError('Failed to load roles: ' + error.message);
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
  
  // Display unified roles view (merged eligible and active)
  function displayUnifiedRoles(eligibleData, activeData) {
    // Clear existing timers
    activeTimerIntervals.forEach(intervalId => clearInterval(intervalId));
    activeTimerIntervals = [];
    
    rolesList.innerHTML = '';

    // Extract eligible roles
    const eligibleDirectoryRoles = eligibleData?.directoryRoles?.value || [];
    const eligibleAzureResourceRoles = eligibleData?.azureResourceRoles?.value || [];
    const eligibleGroupRoles = eligibleData?.groupEligibilities?.value || [];

    // Extract active roles
    const activeDirectoryRoles = activeData?.activeDirectoryRoles?.value || [];
    const activeAzureResourceRoles = activeData?.activeAzureResourceRoles?.value || [];
    const activeGroupMemberships = activeData?.activeGroupMemberships?.value || [];

    // Collect all errors, deduplicating by message text
    const _allErrors = [
      ...(eligibleData?.errors || []),
      ...(activeData?.errors || [])
    ];
    const _seenErrors = new Set();
    const hasGroupData = eligibleGroupRoles.length > 0 ||
      activeGroupMemberships.length > 0 ||
      eligibleDirectoryRoles.some(r => r.assignmentType === 'group') ||
      activeDirectoryRoles.some(r => r.assignmentType === 'group');
    const errors = _allErrors.filter(e => {
      if (_seenErrors.has(e.error)) return false;
      _seenErrors.add(e.error);
      // Suppress "needs PIM token" warnings when group data loaded successfully
      if (hasGroupData && e.needsPimToken) return false;
      // Suppress "no token" group warnings when we already have group data (token is valid)
      if (hasGroupData && e.noToken) return false;
      return true;
    });

    // Display errors if any
    if (errors.length > 0) {
      const criticalErrors = errors.filter(e => !e.warning);
      const warnings = errors.filter(e => e.warning);
      
      if (criticalErrors.length > 0) {
        const errorSection = document.createElement('div');
        errorSection.className = 'warning-section';
        errorSection.innerHTML = '<p><strong>⚠️ Some roles could not be loaded:</strong></p>';
        criticalErrors.forEach(err => {
          const errorMsg = document.createElement('p');
          errorMsg.className = 'error-message';
          errorMsg.textContent = `${err.type}: ${err.error}`;
          errorSection.appendChild(errorMsg);
        });
        rolesList.appendChild(errorSection);
      }
      
      if (warnings.length > 0) {
        const warningSection = document.createElement('div');
        warningSection.className = 'info-section';
        warningSection.innerHTML = '<p><strong>ℹ️ Note:</strong></p>';
        warnings.forEach(warn => {
          const warnMsg = document.createElement('p');
          warnMsg.className = 'info-message';
          warnMsg.textContent = warn.error;
          warningSection.appendChild(warnMsg);
        });
        rolesList.appendChild(warningSection);
      }
    }

    // Create lookup maps for active roles by their unique identifier
    const activeDirectoryMap = new Map();
    activeDirectoryRoles.forEach(role => {
      const key = `${role.roleDefinitionId}-${role.directoryScopeId || '/'}-${role.assignmentType || 'direct'}`;
      activeDirectoryMap.set(key, role);
    });

    const activeAzureResourceMap = new Map();
    activeAzureResourceRoles.forEach(role => {
      const key = `${role.properties?.roleDefinitionId}-${role.properties?.scope}`;
      activeAzureResourceMap.set(key, role);
    });

    const activeGroupMap = new Map();
    activeGroupMemberships.forEach(group => {
      const key = `${group.groupId}-${group.accessId}`;
      activeGroupMap.set(key, group);
    });

    // Build unified role list with status
    const unifiedDirectoryRoles = [];
    const processedDirectoryKeys = new Set();

    // Add eligible directory roles with status
    eligibleDirectoryRoles.forEach(role => {
      const key = `${role.roleDefinitionId}-${role.directoryScopeId || '/'}-${role.assignmentType || 'direct'}`;
      const activeRole = activeDirectoryMap.get(key);
      processedDirectoryKeys.add(key);
      unifiedDirectoryRoles.push({
        ...role,
        status: activeRole ? 'active' : 'eligible',
        activeData: activeRole || null,
        startDateTime: activeRole?.startDateTime || null,
        endDateTime: activeRole?.endDateTime || null
      });
    });

    // Add active-only directory roles (not in eligible list)
    activeDirectoryRoles.forEach(role => {
      const key = `${role.roleDefinitionId}-${role.directoryScopeId || '/'}-${role.assignmentType || 'direct'}`;
      if (!processedDirectoryKeys.has(key)) {
        unifiedDirectoryRoles.push({
          ...role,
          status: 'active',
          activeData: role,
          startDateTime: role.startDateTime,
          endDateTime: role.endDateTime
        });
      }
    });

    // Build unified group list
    const unifiedGroupRoles = [];
    const processedGroupKeys = new Set();

    eligibleGroupRoles.forEach(group => {
      const key = `${group.groupId}-${group.accessId}`;
      const activeGroup = activeGroupMap.get(key);
      processedGroupKeys.add(key);
      unifiedGroupRoles.push({
        ...group,
        status: activeGroup ? 'active' : 'eligible',
        activeData: activeGroup || null,
        startDateTime: activeGroup?.startDateTime || null,
        endDateTime: activeGroup?.endDateTime || null
      });
    });

    activeGroupMemberships.forEach(group => {
      const key = `${group.groupId}-${group.accessId}`;
      if (!processedGroupKeys.has(key)) {
        unifiedGroupRoles.push({
          ...group,
          status: 'active',
          activeData: group,
          startDateTime: group.startDateTime,
          endDateTime: group.endDateTime
        });
      }
    });

    // Build unified Azure resource list
    const unifiedAzureResourceRoles = [];
    const processedAzureKeys = new Set();

    eligibleAzureResourceRoles.forEach(role => {
      const roleDefId = role.properties?.roleDefinitionId || role.roleDefinitionId;
      const scope = role.properties?.scope || '';
      const key = `${roleDefId}-${scope}`;
      const activeRole = activeAzureResourceMap.get(key);
      processedAzureKeys.add(key);
      unifiedAzureResourceRoles.push({
        ...role,
        status: activeRole ? 'active' : 'eligible',
        activeData: activeRole || null,
        startDateTime: activeRole?.properties?.startDateTime || null,
        endDateTime: activeRole?.properties?.endDateTime || null
      });
    });

    activeAzureResourceRoles.forEach(role => {
      const roleDefId = role.properties?.roleDefinitionId;
      const scope = role.properties?.scope;
      const key = `${roleDefId}-${scope}`;
      if (!processedAzureKeys.has(key)) {
        unifiedAzureResourceRoles.push({
          ...role,
          status: 'active',
          activeData: role,
          startDateTime: role.properties?.startDateTime,
          endDateTime: role.properties?.endDateTime
        });
      }
    });

    // Check if we have any roles
    const totalRoles = unifiedDirectoryRoles.length + unifiedGroupRoles.length + unifiedAzureResourceRoles.length;
    if (totalRoles === 0) {
      rolesList.innerHTML += '<p class="no-roles">No PIM roles found for your account.</p>';
      rolesContainer.classList.remove('hidden');
      return;
    }

    // Merge all roles into a single flat list: Direct → Group → Resource, then alphabetical
    function getRoleDisplayName(role, type) {
      if (type === 'directory') return role.roleName || role.roleDefinitionDisplayName || role.roleDefinition?.displayName || '';
      if (type === 'group') return role.groupName || '';
      return role.properties?.expandedProperties?.roleDefinition?.displayName || role.roleName || '';
    }
    function getRoleTypeSortKey(type, assignmentType) {
      if (type === 'azureResource') return 2;
      if (assignmentType === 'group' || type === 'group') return 1;
      return 0; // direct
    }

    const allRoles = [
      ...unifiedDirectoryRoles.map(r => ({ role: r, type: 'directory' })),
      ...unifiedGroupRoles.map(r => ({ role: r, type: 'group' })),
      ...unifiedAzureResourceRoles.map(r => ({ role: r, type: 'azureResource' }))
    ].sort((a, b) => {
      const keyA = getRoleTypeSortKey(a.type, a.role.assignmentType);
      const keyB = getRoleTypeSortKey(b.type, b.role.assignmentType);
      if (keyA !== keyB) return keyA - keyB;
      return getRoleDisplayName(a.role, a.type).localeCompare(getRoleDisplayName(b.role, b.type));
    });

    const allRolesSection = document.createElement('div');
    allRolesSection.className = 'role-section';
    allRoles.forEach(({ role, type }) => {
      const roleElement = createUnifiedRoleElement(role, type);
      allRolesSection.appendChild(roleElement);
    });
    rolesList.appendChild(allRolesSection);

    rolesContainer.classList.remove('hidden');
    filterRoles(); // Apply current filters
  }

  // Helper function to create a unified role element (shows both eligible and active states)
  function createUnifiedRoleElement(role, roleType) {
    const roleElement = document.createElement('div');
    roleElement.className = 'role-item compact';
    roleElement.dataset.status = role.status;

    if (role.status === 'active') {
      roleElement.classList.add('active-role');
    }

    // Store role data based on type
    if (roleType === 'directory') {
      roleElement.dataset.roleDefinitionId = role.roleDefinitionId || '';
      roleElement.dataset.principalId = role.principalId || '';
      roleElement.dataset.directoryScopeId = role.directoryScopeId || '/';
      roleElement.dataset.roleType = 'directory';
      roleElement.dataset.assignmentType = role.assignmentType || 'direct';
      roleElement.dataset.maxDuration = role.maxActivationDuration || 8;

      const roleName = role.roleName || role.roleDefinitionDisplayName || role.roleDefinition?.displayName || 'Unknown Role';
      const roleId = role.roleDefinitionId ? `role-${role.roleDefinitionId.replace(/[-]/g, '')}` : `role-${Math.random().toString(36).substr(2, 9)}`;

      const container = document.createElement('div');
      container.className = 'role-flex-container';

      // Checkbox (only for eligible roles)
      if (role.status === 'eligible') {
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.id = `${roleId}-checkbox`;
        checkbox.className = 'role-checkbox';
        container.appendChild(checkbox);

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
          updateSliderMax();
        });
      }

      const titleDiv = document.createElement('div');
      titleDiv.className = 'role-title-container';
      
      const titleText = document.createElement('div');
      titleText.className = 'role-title';
      titleText.textContent = roleName;
      
      // Assignment type badge
      const badge = document.createElement('span');
      badge.className = 'assignment-badge';
      badge.textContent = role.assignmentType === 'direct' ? 'Direct' : 'Group';
      if (role.assignmentType === 'group') {
        badge.classList.add('assignment-badge-group');
      }
      
      // Status badge
      const statusBadge = document.createElement('span');
      statusBadge.className = `status-badge ${role.status}`;
      statusBadge.textContent = role.status === 'active' ? 'Active' : 'Eligible';

      titleDiv.appendChild(titleText);
      titleDiv.appendChild(badge);
      titleDiv.appendChild(statusBadge);
      
      container.appendChild(titleDiv);

      // Add inline actions for active roles
      if (role.status === 'active' && role.endDateTime) {
        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'inline-role-actions';

        const timerSpan = document.createElement('span');
        timerSpan.className = 'inline-timer';
        const timerId = `timer-${roleId}`;
        timerSpan.id = timerId;
        actionsDiv.appendChild(timerSpan);

        const deactivateBtn = document.createElement('button');
        deactivateBtn.className = 'deactivate-btn-small';
        deactivateBtn.textContent = '✕';
        deactivateBtn.title = 'Deactivate';
        deactivateBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          deactivateRole(role.activeData || role, roleType);
        });
        actionsDiv.appendChild(deactivateBtn);

        container.appendChild(actionsDiv);

        // Start countdown timer
        startInlineCountdown(timerId, role.endDateTime);
      } else if (role.status === 'active') {
        // Active but no end time - just show deactivate button
        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'inline-role-actions';

        const deactivateBtn = document.createElement('button');
        deactivateBtn.className = 'deactivate-btn-small';
        deactivateBtn.textContent = '✕';
        deactivateBtn.title = 'Deactivate';
        deactivateBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          deactivateRole(role.activeData || role, roleType);
        });
        actionsDiv.appendChild(deactivateBtn);

        container.appendChild(actionsDiv);
      }

      roleElement.appendChild(container);
      if (role.status === 'active' && role.startDateTime && role.endDateTime) {
        const timerBar = document.createElement('div');
        timerBar.className = 'activation-timer-bar';
        const timerFill = document.createElement('div');
        timerFill.className = 'activation-timer-fill';
        timerBar.appendChild(timerFill);
        roleElement.appendChild(timerBar);
        startProgressBar(timerFill, role.startDateTime, role.endDateTime);
      }

    } else if (roleType === 'group') {
      roleElement.dataset.groupId = role.groupId || '';
      roleElement.dataset.principalId = role.principalId || '';
      roleElement.dataset.accessId = role.accessId || 'member';
      roleElement.dataset.roleDefinitionId = role.roleDefinitionId || '';
      roleElement.dataset.roleType = 'group';
      roleElement.dataset.assignmentType = 'group';
      roleElement.dataset.maxDuration = role.maxActivationDuration || 8;

      const groupName = role.groupName || 'Unknown Group';
      const accessType = role.accessId === 'owner' ? 'Owner' : 'Member';
      const groupId = role.groupId ? `group-${role.groupId.replace(/[-]/g, '')}` : `group-${Math.random().toString(36).substr(2, 9)}`;

      const container = document.createElement('div');
      container.className = 'role-flex-container';

      // Checkbox (only for eligible)
      if (role.status === 'eligible') {
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.id = `${groupId}-checkbox`;
        checkbox.className = 'role-checkbox';
        container.appendChild(checkbox);

        // Load saved checkbox state
        browser.storage.local.get([`${groupId}-checked`], function(result) {
          if (result[`${groupId}-checked`]) {
            checkbox.checked = true;
          }
        });

        // Save checkbox state when changed
        checkbox.addEventListener('change', function() {
          const saveObj = {};
          saveObj[`${groupId}-checked`] = checkbox.checked;
          browser.storage.local.set(saveObj);
          updateSliderMax();
        });
      }

      const titleContainer = document.createElement('div');
      titleContainer.className = 'role-title-container';
      
      const titleDiv = document.createElement('div');
      titleDiv.className = 'role-title';
      titleDiv.textContent = groupName;
      
      const badge = document.createElement('span');
      badge.className = 'assignment-badge assignment-badge-group';
      badge.textContent = 'Group';
      
      const statusBadge = document.createElement('span');
      statusBadge.className = `status-badge ${role.status}`;
      statusBadge.textContent = role.status === 'active' ? 'Active' : 'Eligible';

      titleContainer.appendChild(titleDiv);
      titleContainer.appendChild(badge);
      titleContainer.appendChild(statusBadge);
      
      container.appendChild(titleContainer);

      // Add inline actions for active roles
      if (role.status === 'active' && role.endDateTime) {
        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'inline-role-actions';

        const timerSpan = document.createElement('span');
        timerSpan.className = 'inline-timer';
        const timerId = `timer-${groupId}`;
        timerSpan.id = timerId;
        actionsDiv.appendChild(timerSpan);

        const deactivateBtn = document.createElement('button');
        deactivateBtn.className = 'deactivate-btn-small';
        deactivateBtn.textContent = '✕';
        deactivateBtn.title = 'Deactivate';
        deactivateBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          deactivateRole(role.activeData || role, roleType);
        });
        actionsDiv.appendChild(deactivateBtn);

        container.appendChild(actionsDiv);
        startInlineCountdown(timerId, role.endDateTime);
      } else if (role.status === 'active') {
        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'inline-role-actions';

        const deactivateBtn = document.createElement('button');
        deactivateBtn.className = 'deactivate-btn-small';
        deactivateBtn.textContent = '✕';
        deactivateBtn.title = 'Deactivate';
        deactivateBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          deactivateRole(role.activeData || role, roleType);
        });
        actionsDiv.appendChild(deactivateBtn);

        container.appendChild(actionsDiv);
      }

      roleElement.appendChild(container);
      if (role.status === 'active' && role.startDateTime && role.endDateTime) {
        const timerBar = document.createElement('div');
        timerBar.className = 'activation-timer-bar';
        const timerFill = document.createElement('div');
        timerFill.className = 'activation-timer-fill';
        timerBar.appendChild(timerFill);
        roleElement.appendChild(timerBar);
        startProgressBar(timerFill, role.startDateTime, role.endDateTime);
      }

    } else if (roleType === 'azureResource') {
      const roleDefinitionId = role.properties?.roleDefinitionId || role.roleDefinitionId || '';
      const principalId = role.properties?.principalId || role.principalId || '';
      const scope = role.properties?.scope || '';

      roleElement.dataset.roleDefinitionId = roleDefinitionId;
      roleElement.dataset.principalId = principalId;
      roleElement.dataset.scope = scope;
      roleElement.dataset.subscriptionId = role.subscriptionId || '';
      roleElement.dataset.roleType = 'azureResource';
      roleElement.dataset.assignmentType = role.assignmentType || 'direct';
      roleElement.dataset.maxDuration = role.maxActivationDuration || 8;

      const roleName = role.properties?.expandedProperties?.roleDefinition?.displayName || role.roleName || 'Unknown Role';
      const subscriptionName = role.subscriptionName || 'Unknown Subscription';
      const scopeDisplay = extractScopeName(scope);

      const roleId = `azrole-${roleDefinitionId.replace(/[^a-zA-Z0-9]/g, '')}${Math.random().toString(36).substr(2, 5)}`;

      const container = document.createElement('div');
      container.className = 'role-flex-container';

      // Checkbox (only for eligible)
      if (role.status === 'eligible') {
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.id = `${roleId}-checkbox`;
        checkbox.className = 'role-checkbox';
        container.appendChild(checkbox);

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
          updateSliderMax();
        });
      }

      const detailsDiv = document.createElement('div');
      detailsDiv.className = 'role-details';
      
      const titleContainer = document.createElement('div');
      titleContainer.className = 'role-title-container';
      
      const titleDiv = document.createElement('div');
      titleDiv.className = 'role-title';
      titleDiv.textContent = roleName;
      
      const badge = document.createElement('span');
      badge.className = 'assignment-badge assignment-badge-resource';
      badge.textContent = 'Resource';

      const statusBadge = document.createElement('span');
      statusBadge.className = `status-badge ${role.status}`;
      statusBadge.textContent = role.status === 'active' ? 'Active' : 'Eligible';

      titleContainer.appendChild(titleDiv);
      titleContainer.appendChild(badge);
      titleContainer.appendChild(statusBadge);
      
      const scopeDiv = document.createElement('div');
      scopeDiv.className = 'role-scope';
      scopeDiv.textContent = subscriptionName + (scopeDisplay ? ` / ${scopeDisplay}` : '');
      
      detailsDiv.appendChild(titleContainer);
      detailsDiv.appendChild(scopeDiv);
      container.appendChild(detailsDiv);

      // Add inline actions for active roles
      if (role.status === 'active' && role.endDateTime) {
        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'inline-role-actions';

        const timerSpan = document.createElement('span');
        timerSpan.className = 'inline-timer';
        const timerId = `timer-${roleId}`;
        timerSpan.id = timerId;
        actionsDiv.appendChild(timerSpan);

        const deactivateBtn = document.createElement('button');
        deactivateBtn.className = 'deactivate-btn-small';
        deactivateBtn.textContent = '✕';
        deactivateBtn.title = 'Deactivate';
        deactivateBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          deactivateRole(role.activeData || role, roleType);
        });
        actionsDiv.appendChild(deactivateBtn);

        container.appendChild(actionsDiv);
        startInlineCountdown(timerId, role.endDateTime);
      } else if (role.status === 'active') {
        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'inline-role-actions';

        const deactivateBtn = document.createElement('button');
        deactivateBtn.className = 'deactivate-btn-small';
        deactivateBtn.textContent = '✕';
        deactivateBtn.title = 'Deactivate';
        deactivateBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          deactivateRole(role.activeData || role, roleType);
        });
        actionsDiv.appendChild(deactivateBtn);

        container.appendChild(actionsDiv);
      }

      roleElement.appendChild(container);
      if (role.status === 'active' && role.startDateTime && role.endDateTime) {
        const timerBar = document.createElement('div');
        timerBar.className = 'activation-timer-bar';
        const timerFill = document.createElement('div');
        timerFill.className = 'activation-timer-fill';
        timerBar.appendChild(timerFill);
        roleElement.appendChild(timerBar);
        startProgressBar(timerFill, role.startDateTime, role.endDateTime);
      }
    }

    return roleElement;
  }

  // Start inline countdown timer for active roles
  function startInlineCountdown(timerId, endDateTime) {
    const timerElement = document.getElementById(timerId);
    if (!timerElement) return;

    const endTime = new Date(endDateTime).getTime();

    function updateTimer() {
      const now = Date.now();
      const remaining = endTime - now;

      if (remaining <= 0) {
        timerElement.textContent = 'Expired';
        timerElement.classList.add('expired');
        return;
      }

      const hours = Math.floor(remaining / (1000 * 60 * 60));
      const minutes = Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((remaining % (1000 * 60)) / 1000);

      if (hours > 0) {
        timerElement.textContent = `${hours}h ${minutes}m`;
      } else if (minutes > 0) {
        timerElement.textContent = `${minutes}m ${seconds}s`;
      } else {
        timerElement.textContent = `${seconds}s`;
      }

      // Add warning style if less than 15 minutes
      if (remaining < 15 * 60 * 1000) {
        timerElement.classList.add('expiring-soon');
      }
    }

    updateTimer();
    const intervalId = setInterval(updateTimer, 1000);
    activeTimerIntervals.push(intervalId);
  }

  function startProgressBar(fillElement, startDateTime, endDateTime) {
    const startTime = new Date(startDateTime).getTime();
    const endTime = new Date(endDateTime).getTime();
    const totalDuration = endTime - startTime;

    function updateBar() {
      const now = Date.now();
      const remaining = Math.max(0, endTime - now);
      const pct = totalDuration > 0 ? (remaining / totalDuration) * 100 : 0;
      fillElement.style.width = `${pct}%`;
      if (remaining < 15 * 60 * 1000) {
        fillElement.classList.add('expiring-soon');
      }
    }

    updateBar();
    const intervalId = setInterval(updateBar, 10000);
    activeTimerIntervals.push(intervalId);
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

        if (roleType === 'group') {
          // PIM group eligibility
          const groupId = roleItem.dataset.groupId;
          const principalId = roleItem.dataset.principalId;
          const roleDefinitionId = roleItem.dataset.roleDefinitionId;
          
          selectedRoles.push({
            roleType: 'group',
            groupId: groupId,
            principalId: principalId,
            accessId: roleItem.dataset.accessId || 'member',
            roleDefinitionId: roleDefinitionId,
            groupName: roleTitleElement ? roleTitleElement.textContent : 'Unknown Group'
          });
        } else if (roleType === 'azureResource') {
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
    let visibleCount = 0;
    let totalCount = allRoleItems.length;

    allRoleItems.forEach(roleItem => {
      const roleType = roleItem.dataset.roleType;
      const roleStatus = roleItem.dataset.status;
      const roleTitleElement = roleItem.querySelector('.role-title');
      const roleScopeElement = roleItem.querySelector('.role-scope');

      const roleName = roleTitleElement ? roleTitleElement.textContent.toLowerCase() : '';
      const roleScope = roleScopeElement ? roleScopeElement.textContent.toLowerCase() : '';

      // Check filter type
      const assignmentType = roleItem.dataset.assignmentType;
      let matchesFilter = true;
      if (currentFilter === 'directory') {
        // "Direct" shows only directory roles assigned directly (not via a group)
        matchesFilter = roleType === 'directory' && assignmentType === 'direct';
      } else if (currentFilter === 'group') {
        // "PIM Groups" shows PIM group memberships AND directory roles inherited via a group
        matchesFilter = roleType === 'group' || (roleType === 'directory' && assignmentType === 'group');
      } else if (currentFilter === 'azureResource') {
        matchesFilter = roleType === 'azureResource';
      }

      // Check status filter
      let matchesStatus = true;
      if (currentStatusFilter === 'eligible') {
        matchesStatus = roleStatus === 'eligible';
      } else if (currentStatusFilter === 'active') {
        matchesStatus = roleStatus === 'active';
      }

      // Check search term
      let matchesSearch = true;
      if (currentSearchTerm) {
        matchesSearch = roleName.includes(currentSearchTerm) || roleScope.includes(currentSearchTerm);
      }

      // Show/hide based on all criteria
      const shouldShow = matchesFilter && matchesStatus && matchesSearch;
      roleItem.style.display = shouldShow ? '' : 'none';

      if (shouldShow) {
        visibleCount++;
      }
    });

    // Update results count
    updateSearchResultsCount(visibleCount, totalCount);

    // Show/hide "no results" message
    updateNoResultsMessage(visibleCount);
  }

  // Update search results count display
  function updateSearchResultsCount(visible, total) {
    if (currentSearchTerm || currentFilter !== 'all' || currentStatusFilter !== 'all') {
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
    if (visibleCount === 0 && (currentSearchTerm || currentFilter !== 'all' || currentStatusFilter !== 'all')) {
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

  // Deactivate a role
  async function deactivateRole(role, roleType) {
    let roleName;
    if (roleType === 'directory') {
      roleName = role.roleName || role.roleDefinition?.displayName || 'this role';
    } else if (roleType === 'group') {
      roleName = role.groupName || 'this group';
    } else {
      roleName = role.properties?.expandedProperties?.roleDefinition?.displayName || 'this role';
    }
    
    if (!confirm(`Are you sure you want to deactivate "${roleName}"?`)) {
      return;
    }

    // Show loading state
    statusMessage.textContent = `Deactivating ${roleName}...`;

    try {
      if (roleType === 'directory') {
        await deactivateDirectoryRole(role);
      } else if (roleType === 'group') {
        await deactivateGroupMembership(role);
      } else if (roleType === 'azureResource') {
        await deactivateAzureResourceRole(role);
      }

      statusMessage.textContent = `Successfully deactivated ${roleName}`;
      
      // Reload roles after a delay to allow API to update
      setTimeout(() => {
        statusMessage.textContent = currentUpn ? `Loading roles for ${currentUpn}` : 'Reloading roles ..';
        loadAllRolesUnified(false);
      }, 2000);
    } catch (error) {
      showError(`Failed to deactivate ${roleName}: ${error.message}`);
    }
  }

  // Deactivate a directory role
  async function deactivateDirectoryRole(role) {
    const response = await browser.runtime.sendMessage({
      action: 'getTokens',
      cookieStoreId: currentCookieStoreId
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
        return { alreadyDeactivated: true };
      }
      
      throw new Error(errorMessage);
    }

    return await apiResponse.json();
  }

  // Deactivate an Azure resource role
  async function deactivateAzureResourceRole(role) {
    const response = await browser.runtime.sendMessage({
      action: 'getTokens',
      cookieStoreId: currentCookieStoreId
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
        return { alreadyDeactivated: true };
      }
      
      throw new Error(errorMessage);
    }

    return await apiResponse.json();
  }

  // Deactivate a PIM group membership
  async function deactivateGroupMembership(group) {
    const response = await browser.runtime.sendMessage({
      action: 'getTokens',
      cookieStoreId: currentCookieStoreId
    });

    if (!response || !response.success || !response.tokens.graphToken) {
      throw new Error('No Graph API token available. Please visit Microsoft Entra portal.');
    }

    const token = response.tokens.graphToken;
    const principalId = group.principalId;
    const groupId = group.groupId;

    // Use Graph API format for deactivation
    const requestBody = {
      "action": "selfDeactivate",
      "accessId": group.accessId || "member",
      "principalId": principalId,
      "groupId": groupId,
      "justification": "Self-deactivation via PIMfox"
    };

    const apiResponse = await fetch(
      'https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests',
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
      const errorMessage = errorData.error?.message || errorData.message || `HTTP ${apiResponse.status}`;

      // Check if group membership is already deactivated
      if (apiResponse.status === 400 && (errorMessage.includes('does not exist') || errorMessage.includes('not active') || errorMessage.includes('No active assignment'))) {
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

});
