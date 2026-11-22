-- SPDX-License-Identifier: AGPL-3.0-only
WITH scope(relation_pattern, function_pattern, extra_functions) AS (
 SELECT '^external_observation_', 'external_observation', ARRAY[]::text[]
),
