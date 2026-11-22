-- SPDX-License-Identifier: AGPL-3.0-only
WITH scope(relation_pattern, function_pattern, extra_functions) AS (
 SELECT '^application_ownership', 'application_ownership', ARRAY['external_observation_lock_organization','external_observation_lock_application']::text[]
),
