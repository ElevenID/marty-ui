// Archived manifests retain provenance; current platform routes and cards only
// expose platform-owned demonstrations. D-07 remains reserved to its old owner.
export function platformDemoScenarios(scenarios) {
  return scenarios.filter((scenario) => scenario.slug !== 'canvas-learning-achievement'
    && scenario.demo_id !== 'D-07');
}
