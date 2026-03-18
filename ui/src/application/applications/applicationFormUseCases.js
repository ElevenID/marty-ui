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
  createApplication,
  autoIssueApplication,
}) {
  let applicantId = await resolveApplicantId();

  if (!applicantId) {
    const createdApplicant = await createApplicant({
      organization_id: organizationId,
      user_id: user.user_id,
      given_name: user.given_name || '',
      family_name: user.family_name || '',
      email: user.email,
    });
    applicantId = createdApplicant?.id || null;
  }

  if (!applicantId) {
    throw new Error('Unable to resolve applicant profile');
  }

  const autoApplyContext = buildAutoApplyContext({
    credentialConfig,
    user,
    organizationId,
  });

  const createdApplication = await createApplication({
    applicant_id: applicantId,
    credential_configuration_id: credentialConfig?.id || credentialConfigId,
    issuing_authority: 'Marty Trust Services',
    requested_validity_years: autoApplyContext.requested_validity_years,
    metadata: autoApplyContext.metadata,
  });

  const issuedApplication = await autoIssueApplication(createdApplication.id);

  return {
    applicationId: issuedApplication.id,
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
    submitted: true,
  };
}
