import {
  buildApplicantProfileData,
  buildAutoApplyContext,
  buildStandardApplicationPayload,
  normalizeApplicationTemplateToFormConfig,
  normalizeCredentialConfigInput,
  normalizeTemplateToFormConfig,
} from './applicationFlow';

const DUPLICATE_ACTIVE_APPLICATION_STATUSES = new Set([
  'DRAFT',
  'SUBMITTED',
  'UNDER_REVIEW',
  'PENDING_INFORMATION',
  'APPROVED',
  'OFFERED',
  'CREDENTIALED',
  'ISSUED',
]);

function normalizeApplicationsResponse(data) {
  if (Array.isArray(data)) {
    return data;
  }

  return Array.isArray(data?.applications) ? data.applications : [];
}

function applicationStatus(application) {
  return String(application?.status || '').trim().toUpperCase();
}

export function findActiveApplicationForCredential(applications = [], credentialConfigId) {
  if (!credentialConfigId) {
    return null;
  }

  return normalizeApplicationsResponse(applications)
    .filter((application) => application?.credential_configuration_id === credentialConfigId)
    .filter((application) => DUPLICATE_ACTIVE_APPLICATION_STATUSES.has(applicationStatus(application)))
    .sort((a, b) => new Date(b?.updated_at || b?.updatedAt || b?.created_at || 0) - new Date(a?.updated_at || a?.updatedAt || a?.created_at || 0))[0] || null;
}

export async function loadCredentialApplicationConfig({
  credentialConfigId,
  credentialConfig,
  organizationId,
  getCredentialTemplate,
  applicationTemplateId = null,
  getApplicationTemplate = null,
}) {
  if ((!credentialConfigId || credentialConfig) && (!applicationTemplateId || !getApplicationTemplate)) {
    return {
      credentialConfig,
      applicationTemplate: null,
      error: null,
    };
  }

  if (!organizationId && credentialConfigId && !credentialConfig && !applicationTemplateId) {
    return {
      credentialConfig: null,
      applicationTemplate: null,
      error: 'Organization context missing for credential configuration.',
    };
  }

  const template = credentialConfig || (credentialConfigId ? await getCredentialTemplate(credentialConfigId) : null);
  const normalizedCredentialConfig = credentialConfig
    ? normalizeCredentialConfigInput(credentialConfig)
    : (template ? normalizeTemplateToFormConfig(template) : null);
  const applicationTemplate = applicationTemplateId && getApplicationTemplate
    ? await getApplicationTemplate(applicationTemplateId)
    : null;

  return {
    credentialConfig: applicationTemplate
      ? normalizeApplicationTemplateToFormConfig(applicationTemplate, normalizedCredentialConfig)
      : normalizedCredentialConfig,
    applicationTemplate,
    error: null,
  };
}

export async function resolveApplicantIdForApplication({ user, getApplicant, getApplicantByUser }) {
  if (user?.applicant_id) {
    try {
      const applicant = await getApplicant(user.applicant_id);
      if (applicant?.id) {
        return applicant.id;
      }
    } catch {
      // Fall through to user lookup.
    }
  }

  if (!user?.user_id) {
    return null;
  }

  const applicant = await getApplicantByUser(user.user_id);
  return applicant?.id || null;
}

export async function ensureApplicantProfileForApplication({
  organizationId,
  user,
  formData,
  resolveApplicantId,
  createApplicant,
  updateApplicantProfile,
  getApplicantByUser,
}) {
  const applicantData = buildApplicantProfileData({
    organizationId,
    user,
    formData,
  });

  let applicantId = await resolveApplicantId();
  let applicantCreated = false;

  if (!applicantId) {
    const createdApplicant = await createApplicant(applicantData);
    applicantId = createdApplicant?.id || null;
    applicantCreated = true;
  }

  if (!applicantId) {
    throw new Error('Unable to resolve applicant profile');
  }

  if (!applicantCreated) {
    try {
      await updateApplicantProfile(applicantId, applicantData);
    } catch (error) {
      if (error?.status === 404) {
        const fallbackApplicant = await getApplicantByUser(user?.user_id);
        if (fallbackApplicant?.id) {
          applicantId = fallbackApplicant.id;
        } else {
          const recreatedApplicant = await createApplicant(applicantData);
          applicantId = recreatedApplicant?.id || null;
          applicantCreated = true;
        }

        if (!applicantId) {
          throw new Error('Unable to resolve applicant profile');
        }
      } else {
        throw error;
      }
    }
  }

  return {
    applicantId,
    applicantCreated,
    applicantData,
  };
}

export async function autoApplyForCredential({
  organizationId,
  user,
  credentialConfig,
  credentialConfigId,
  hasRegisteredWallet = true,
  resolveApplicantId,
  createApplicant,
  updateApplicantProfile,
  createApplication,
  submitApplication,
  autoIssueApplication,
  generateIssuanceOffer,
  listApplications,
}) {
  const buildOfferData = (record) => ({
    offer_url: record?.credential_offer_uri || record?.offer_url || null,
    credential_offer_uris: record?.credential_offer_uris || {},
    expires_at: record?.offer_expires_at || record?.expires_at || null,
  });

  let applicantId = await resolveApplicantId();
  let applicantCreated = false;

  if (!applicantId) {
    const createdApplicant = await createApplicant({
      organization_id: organizationId,
      user_id: user.user_id,
      given_name: user.given_name || '',
      family_name: user.family_name || '',
      email: user.email,
    });
    applicantId = createdApplicant?.id || null;
    applicantCreated = true;
  }

  if (!applicantId) {
    throw new Error('Unable to resolve applicant profile');
  }

  if (!applicantCreated && updateApplicantProfile) {
    await updateApplicantProfile(applicantId, {
      email: user.email,
      given_name: user.given_name || '',
      family_name: user.family_name || '',
    });
  }

  // Check for an existing active application for this credential type.
  // If one already exists (credentialed / approved), return its offer
  // instead of creating a duplicate.
  const configId = credentialConfig?.id || credentialConfigId;
  if (listApplications) {
    try {
      const { applications = [] } = await listApplications({ limit: 100 });
      const existing = applications.find((a) => {
        const status = a.status?.toLowerCase();
        return (
          a.credential_configuration_id === configId &&
          ['approved', 'offered', 'credentialed', 'issued'].includes(status)
        );
      });
      if (existing) {
        const status = existing.status?.toLowerCase();
        if (hasRegisteredWallet && generateIssuanceOffer) {
          const refreshedApplication = await generateIssuanceOffer(existing.id);
          return {
            applicationId: refreshedApplication.id || existing.id,
            applicationReference: refreshedApplication.reference_number || refreshedApplication.referenceNumber || existing.reference_number || existing.referenceNumber || null,
            offerData: buildOfferData(refreshedApplication),
            existingApplication: true,
          };
        }

        if (hasRegisteredWallet && ['approved', 'offered'].includes(status) && autoIssueApplication) {
          const refreshedApplication = await autoIssueApplication(existing.id);
          return {
            applicationId: refreshedApplication.id,
            applicationReference: refreshedApplication.reference_number || refreshedApplication.referenceNumber || existing.reference_number || existing.referenceNumber || null,
            offerData: buildOfferData(refreshedApplication),
            existingApplication: true,
          };
        }
        return {
          applicationId: existing.id,
          applicationReference: existing.reference_number || existing.referenceNumber || null,
          offerData: buildOfferData(existing),
          existingApplication: true,
          requiresWalletSelection: !hasRegisteredWallet,
        };
      }
    } catch {
      // If listing fails, proceed with creation and let the backend guard catch duplicates
    }
  }

  const autoApplyContext = buildAutoApplyContext({
    credentialConfig,
    user,
    organizationId,
  });

  const createdApplication = await createApplication({
    applicant_id: applicantId,
    credential_configuration_id: credentialConfig?.id || credentialConfigId,
    issuing_authority: 'ElevenID LLC',
    requested_validity_years: autoApplyContext.requested_validity_years,
    metadata: autoApplyContext.metadata,
  });

  const submittedApplication = submitApplication
    ? await submitApplication(createdApplication.id)
    : createdApplication;

  if (!hasRegisteredWallet) {
    return {
      applicationId: submittedApplication.id,
      applicationReference: submittedApplication.reference_number || submittedApplication.referenceNumber || createdApplication.reference_number || createdApplication.referenceNumber || null,
      offerData: buildOfferData(submittedApplication),
      requiresWalletSelection: true,
    };
  }

  const issuedApplication = generateIssuanceOffer
    ? await generateIssuanceOffer(submittedApplication.id)
    : (autoIssueApplication ? await autoIssueApplication(submittedApplication.id) : submittedApplication);

  return {
    applicationId: issuedApplication.id,
    applicationReference: issuedApplication.reference_number || issuedApplication.referenceNumber || submittedApplication.reference_number || submittedApplication.referenceNumber || createdApplication.reference_number || createdApplication.referenceNumber || null,
    offerData: buildOfferData(issuedApplication),
  };
}

export async function submitCredentialApplication({
  organizationId,
  user,
  formData,
  credentialConfig,
  credentialConfigId,
  canvasLtiContext = null,
  allFields,
  resolveApplicantId,
  createApplicant,
  updateApplicantProfile,
  getApplicantByUser,
  createApplication,
  submitApplication,
  listApplicantApplications = null,
  supersedeApplication = null,
  duplicateApplicationAction = null,
  enrollBiometric,
  readFileAsBase64,
  createFallbackBiometricTemplate = () => btoa('test-biometric-template'),
}) {
  if (!credentialConfig?.id && !credentialConfigId) {
    throw new Error('Please select a credential to apply for.');
  }

  const { applicantId } = await ensureApplicantProfileForApplication({
    organizationId,
    user,
    formData,
    resolveApplicantId,
    createApplicant,
    updateApplicantProfile,
    getApplicantByUser,
  });

  const effectiveCredentialConfigId = credentialConfig?.id || credentialConfigId;
  if (listApplicantApplications) {
    const existingApplications = await listApplicantApplications(applicantId);
    const duplicate = findActiveApplicationForCredential(existingApplications, effectiveCredentialConfigId);
    if (duplicate) {
      if (duplicateApplicationAction === 'continue') {
        return {
          applicationId: duplicate.id,
          applicationReference: duplicate.reference_number || duplicate.referenceNumber || null,
          existingApplication: true,
          submitted: true,
        };
      }

      if (duplicateApplicationAction === 'replace') {
        if (!supersedeApplication) {
          throw new Error('Unable to replace the previous application.');
        }
        await supersedeApplication(duplicate.id, {
          reason: 'superseded_by_reapplication',
          replacement_credential_configuration_id: effectiveCredentialConfigId,
          source: canvasLtiContext ? 'canvas_lti_reapplication' : 'applicant_reapplication',
        });
      } else {
        return {
          duplicateApplicationConflict: {
            existingApplication: duplicate,
            credentialConfigId: effectiveCredentialConfigId,
          },
          submitted: false,
        };
      }
    }
  }

  const createdApplication = await createApplication(
    buildStandardApplicationPayload({
      applicantId,
      credentialConfig,
      credentialConfigId,
      formData,
      canvasLtiContext,
    })
  );

  const submittedApplication = await submitApplication(createdApplication.id);

  const portraitField = allFields.find((field) => field.name === 'portrait' || field.type === 'file');
  if (portraitField && formData[portraitField.name]) {
    const imageBase64 = await readFileAsBase64(formData[portraitField.name]);
    const templateBase64 = imageBase64 || createFallbackBiometricTemplate();

    await enrollBiometric(applicantId, {
      biometric_type: 'FACIAL',
      template_data_base64: templateBase64,
      image_data_base64: imageBase64,
      is_live_capture: true,
      capture_device_id: 'web-form',
    });
  }

  return {
    applicationId: submittedApplication.id,
    applicationReference: submittedApplication.reference_number || submittedApplication.referenceNumber || createdApplication.reference_number || createdApplication.referenceNumber || null,
    submitted: true,
  };
}

