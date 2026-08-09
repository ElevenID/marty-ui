import {
  buildApplicantProfileData,
  buildAutoApplyFormData,
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

const APPLICANT_UPLOAD_EVIDENCE_TYPES = new Set([
  'DOCUMENT_SCAN',
  'BIOMETRIC',
  'SELFIE',
  'THIRD_PARTY_VERIFICATION',
]);

export function applicationEvidenceUploads({ credentialConfig, formData }) {
  return (credentialConfig?.evidence_requirements || [])
    .filter((requirement) => APPLICANT_UPLOAD_EVIDENCE_TYPES.has(
      String(requirement?.evidence_type || '').toUpperCase()
    ))
    .map((requirement) => ({
      requirement,
      file: formData?.[requirement.evidence_id],
    }))
    .filter(({ requirement, file }) => {
      if (requirement.required && !file) {
        throw new Error(`Upload ${requirement.description || requirement.evidence_id} before submitting.`);
      }
      return Boolean(file);
    });
}

function normalizeApplicationsResponse(data) {
  return Array.isArray(data) ? data : [];
}

function applicationStatus(application) {
  return String(application?.status || '').trim().toUpperCase();
}

export function findActiveApplicationForCredential(applications = [], credentialConfigId) {
  if (!credentialConfigId) {
    return null;
  }

  return normalizeApplicationsResponse(applications)
    .filter((application) => application?.credential_template_id === credentialConfigId)
    .filter((application) => DUPLICATE_ACTIVE_APPLICATION_STATUSES.has(applicationStatus(application)))
    .sort((a, b) => new Date(b?.updated_at || b?.created_at || 0) - new Date(a?.updated_at || a?.created_at || 0))[0] || null;
}

export async function loadCredentialApplicationConfig({
  credentialConfigId,
  credentialConfig,
  organizationId,
  getCredentialTemplate,
  applicationTemplateId = null,
  getApplicationTemplate = null,
  listApplicationTemplates = null,
}) {
  const shouldResolveLinkedTemplate = Boolean(
    organizationId
    && listApplicationTemplates
    && (credentialConfig?.id || credentialConfigId)
    && !applicationTemplateId
    && !credentialConfig?.application_template_id
  );
  if ((!credentialConfigId || credentialConfig) && (!applicationTemplateId || !getApplicationTemplate) && !shouldResolveLinkedTemplate) {
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
  const linkedTemplateId = applicationTemplateId || normalizedCredentialConfig?.application_template_id;
  let applicationTemplate = linkedTemplateId && getApplicationTemplate
    ? await getApplicationTemplate(linkedTemplateId)
    : null;

  if (!applicationTemplate && organizationId && listApplicationTemplates && normalizedCredentialConfig?.id) {
    const templates = await listApplicationTemplates(organizationId);
    applicationTemplate = (Array.isArray(templates) ? templates : [])
      .find((candidate) => (
        candidate?.credential_template_id === normalizedCredentialConfig.id
        && String(candidate?.status || '').trim().toUpperCase() === 'ACTIVE'
      )) || null;
  }

  return {
    credentialConfig: applicationTemplate
      ? normalizeApplicationTemplateToFormConfig(applicationTemplate, normalizedCredentialConfig)
      : normalizedCredentialConfig,
    applicationTemplate,
    error: null,
  };
}

export async function resolveApplicantIdForApplication({ user, getApplicant, getApplicantByUser }) {
  const userId = user?.user_id;
  const applicantIdFromAuth = user?.applicant_id;

  if (applicantIdFromAuth && applicantIdFromAuth !== userId) {
    try {
      const applicant = await getApplicant(applicantIdFromAuth);
      if (applicant?.id) {
        return applicant.id;
      }
    } catch {
      // Fall through to user lookup.
    }
  }

  if (!userId) {
    return null;
  }

  const applicant = await getApplicantByUser(userId);
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
          throw new Error('Unable to resolve applicant profile', { cause: error });
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
  applicationTemplate,
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
      const { items } = await listApplications({ limit: 100 });
      const existing = items.find((a) => {
        const status = a.status?.toLowerCase();
        return (
          a.credential_template_id === configId &&
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

  const formData = buildAutoApplyFormData({ applicationTemplate, user });

  const createdApplication = await createApplication({
    organization_id: organizationId,
    application_template_id: applicationTemplate.id,
    form_data: formData,
    integration_context: {},
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
  submitApplicationEvidence,
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

  const evidenceUploads = applicationEvidenceUploads({ credentialConfig, formData });
  if (evidenceUploads.length > 0 && !submitApplicationEvidence) {
    throw new Error('Application evidence upload is unavailable.');
  }

  const createdApplication = await createApplication(
    buildStandardApplicationPayload({
      organizationId,
      credentialConfig,
      formData,
      canvasLtiContext,
    })
  );

  for (const { requirement, file } of evidenceUploads) {
    const contentBase64 = await readFileAsBase64(file);
    if (!contentBase64) {
      throw new Error(`Unable to read ${requirement.description || requirement.evidence_id}.`);
    }
    const acceptedMimeType = (requirement.accepted_formats || [])
      .find((value) => String(value).includes('/'));
    await submitApplicationEvidence(createdApplication.id, {
      evidence_requirement_id: requirement.evidence_id,
      media_type: file.type || acceptedMimeType || 'application/octet-stream',
      filename: file.name || `${requirement.evidence_id}.bin`,
      content_base64: contentBase64,
      captured_at: new Date().toISOString(),
    });
  }

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

