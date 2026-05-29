# Changelog

## 1.4.0
- Added: Firefox Multi-Account Containers support — when multiple containers are open, each container maintains its own independent token and role cache. PIMfox shows the correct account's roles based on whichever container's tab is currently active, enabling multi-account and multi-tenant workflows side-by-side.
- Improved: The status bar now shows "Loading roles for [ID]" or "Roles loaded for [ID]", giving you a visual security context used for role fetching and display.
- Fixed: Azure active resource roles used wall-clock time since token capture to determine whether the token had expired. The extension now reads the `exp` claim embedded in the JWT itself, consistent with how other token types are checked.
- Fixed: PIM Groups functionality now use the Graph API exclusively.
- Fixed: Removed delay in token status detection that could incorrectly report no token available if decryption of a stored token took slightly longer than expected.

## 1.3.2
- Fixed: PIM Groups and Azure resource roles no longer falsely report an expired token when your session is still valid but the token was captured more than 45 minutes ago. The extension previously used the time since token capture as a proxy for expiry, which could block role loading for users with longer-lived sessions (e.g. due to Continuous Access Evaluation or extended token lifetimes configured in Entra ID).
- Fixed: Expired tokens are now reliably detected even if they were captured very recently — the extension reads the actual expiration timestamp (`exp` claim) embedded in the token itself, rather than assuming a fixed 45-minute lifetime.
- Fixed: If your PIM Groups token has expired, the error message now instructs you to hard-reload the Azure Portal PIM Groups page (Ctrl+Shift+R) to force a fresh token to be issued and captured, rather than just navigating to the page.
- Improved: Token expiry detection now falls back gracefully to the 45-minute wall-clock estimate only if the token cannot be decoded — ensuring backward compatibility in edge cases.

## 1.3.1
- All roles (Direct, Group and Resource) now use unified list, sorted by type (Direct → Group → Resource) and then alphabetically
- Each role card shows a type badge (Direct, Group, Resource) and a status badge (Eligible, Active)
- Active roles now show a time-remaining progress bar at the bottom of their card; the bar turns orange when less than 15 minutes remain
- Fixed: an active direct role assignment no longer incorrectly marks the same role's group-inherited assignment as active
- Fixed: the PIM Groups token warning no longer appears when group-based PIM roles already in the list

## 1.3.0
- Added dark mode with toggle button (initial state follows OS preference, persisted per browser)
- Fixed "Direct" filter: now shows only roles assigned directly, excluding group-inherited directory roles
- Fixed "PIM Groups" filter: now also shows Entra directory roles that are inherited via group membership
- Fixed false "token may have expired" warnings by checking Graph token PIM scopes before calling PIM endpoints, with an actionable error message pointing to the right portal page
- Clarified PIM Groups token error messages to distinguish the PIM Groups token from the main Graph token

## 1.2.0
- Slider maximum now adjusts to the lowest allowed activation duration across selected roles, PIM groups and Azure resources (capped at 8 hours)
- Filter chip clicks now invalidate the role cache so the next popup open fetches fresh data

## 1.1.0
- Added support for PIM Groups
- Added success message when activating

## 1.0.0
- Initial release
