import {
  buildApplicantProfileData,
  buildAutoApplyContext,
  buildStandardApplicationPayload,
  normalizeTemplateToFormConfig,
} from './applicationFlow';

export async function loadCredentialApplicationConfig({
  credentialConfigId,
  credentialConfig,
  organizationId,
  getCredentialTemplate,
}) {
  if (!credentialConfigId || credentialConfig) {
    return {
      credentialConfig,
      error: null,
    };
  }

  if (!organizationId) {
    return {
      credentialConfig: null,
      error: 'Organization context missing for credential configuration.',
    };
  }

  const template = await getCredentialTemplate(credentialConfigId);

  return {
    credentialConfig: normalizeTemplateToFormConfig(template),
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
  resolveApplicantId,
  createApplicant,
  updateApplicantProfile,
  createApplication,
  autoIssueApplication,
  listApplications,
}) {
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
        if (['approved', 'offered'].includes(status) && autoIssueApplication) {
          const refreshedApplication = await autoIssueApplication(existing.id);
          return {
            applicationId: refreshedApplication.id,
            applicationReference: refreshedApplication.reference_number || refreshedApplication.referenceNumber || existing.reference_number || existing.referenceNumber || null,
            offerData: {
              offer_url: refreshedApplication.credential_offer_uri || null,
              credential_offer_uris: refreshedApplication.credential_offer_uris || {},
              expires_at: refreshedApplication.offer_expires_at || null,
            },
            existingApplication: true,
          };
        }
        return {
          applicationId: existing.id,
          applicationReference: existing.reference_number || existing.referenceNumber || null,
          offerData: {
            offer_url: existing.credential_offer_uri || null,
            credential_offer_uris: existing.credential_offer_uris || {},
            expires_at: existing.offer_expires_at || null,
          },
          existingApplication: true,
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

  const issuedApplication = await autoIssueApplication(createdApplication.id);

  return {
    applicationId: issuedApplication.id,
    applicationReference: issuedApplication.reference_number || issuedApplication.referenceNumber || createdApplication.reference_number || createdApplication.referenceNumber || null,
    offerData: {
      offer_url: issuedApplication.credential_offer_uri,
      credential_offer_uris: issuedApplication.credential_offer_uris || {},
      expires_at: issuedApplication.offer_expires_at,
    },
  };
}

export async function submitCredentialApplication({
  organizationId,
  user,
  formData,
  credentialConfig,
  credentialConfigId,
  allFields,
  resolveApplicantId,
  createApplicant,
  updateApplicantProfile,
  getApplicantByUser,
  createApplication,
  submitApplication,
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

  const createdApplication = await createApplication(
    buildStandardApplicationPayload({
      applicantId,
      credentialConfig,
      credentialConfigId,
      formData,
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
