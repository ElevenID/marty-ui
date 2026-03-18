# Deprecated UI dead code

These files were removed from live component paths on 2026-03-17 after an import audit showed they were not referenced by `App.jsx`, active layouts, or any live component imports.

Old import paths were intentionally removed so new work cannot accidentally build on dead UI code.

## Removed legacy components

- `MyApplications.jsx` — legacy applicant page superseded by applicant console routes and `console/applicant/MyApplicationsPage.jsx`
- `MyDocuments.jsx` — legacy applicant document page superseded by applicant console views and newer applicant flows
- `OnboardingPage.jsx` — legacy monolithic onboarding flow superseded by the split onboarding/application-layer flow and current join/setup routes
- `ZkVerificationComponent.jsx` — unreferenced experimental component with no live imports or routes

## Policy

Do not restore imports from the old paths.
If equivalent functionality is needed, build on the active routed components and the `src/application/**` slices instead.
