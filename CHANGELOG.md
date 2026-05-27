# Changelog

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
