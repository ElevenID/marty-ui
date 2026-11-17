// Archived manifests retain provenance; current platform routes and cards only
// expose platform-owned demonstrations. D-07 and D-08 remain reserved outside the active platform portfolio.
export function platformDemoScenarios(scenarios) {
  return scenarios.filter((scenario) => scenario.slug !== 'canvas-learning-achievement'
    && scenario.demo_id !== 'D-07'
    && scenario.slug !== 'external-evidence-to-credential'
    && scenario.demo_id !== 'D-08');
}
