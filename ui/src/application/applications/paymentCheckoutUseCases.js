export function buildPaymentCheckoutInitialBillingInfo(user = {}) {
  return {
    name: user?.name || '',
    email: user?.email || '',
    address: '',
    city: '',
    state: '',
    zip: '',
    country: 'US',
  };
}

export function updatePaymentCheckoutBillingInfo(billingInfo, field, value) {
  return {
    ...billingInfo,
    [field]: value,
  };
}

export function validatePaymentCheckoutBilling(billingInfo = {}) {
  const required = ['name', 'email', 'address', 'city', 'state', 'zip'];
  return required.every((field) => billingInfo[field]?.trim());
}

export async function initializePaymentCheckout({
  credential,
  processingFee,
  navigate,
  initializePayment,
  containerId = 'card-container',
}) {
  if (!credential) {
    navigate('/credentials');
    return {
      redirected: true,
      error: null,
    };
  }

  if (processingFee <= 0) {
    return {
      redirected: false,
      error: null,
    };
  }

  const result = await initializePayment(containerId);

  return {
    redirected: false,
    error: result?.success ? null : (result?.error || 'Failed to load payment form. Please refresh and try again.'),
  };
}

export function buildPaymentCheckoutMetadata({ credential, user, billingInfo }) {
  return {
    billingContact: billingInfo,
    metadata: {
      credentialId: credential?.id,
      credentialName: credential?.name,
      applicantEmail: user?.email,
    },
  };
}

export function buildPaymentCheckoutSubmissionPayload({ credential, processingFee, billingInfo, paymentResult }) {
  return {
    credentialId: credential.id,
    credentialType: credential.id,
    paymentId: paymentResult?.paymentId,
    processingFee,
    billingInfo,
  };
}

export function buildPaymentCheckoutReceipt({ applicationId, paymentResult, processingFee, credentialName, nowIso, warning = null }) {
  return {
    applicationId,
    paymentId: paymentResult?.paymentId,
    amount: processingFee,
    date: nowIso,
    credentialName,
    warning,
  };
}

export async function submitPaymentCheckoutApplication({
  submitCheckoutApplication,
  credential,
  processingFee,
  billingInfo,
  paymentResult,
  nowIso = new Date().toISOString(),
}) {
  try {
    const result = await submitCheckoutApplication(
      buildPaymentCheckoutSubmissionPayload({
        credential,
        processingFee,
        billingInfo,
        paymentResult,
      })
    );

    return {
      receiptData: buildPaymentCheckoutReceipt({
        applicationId: result?.applicationId,
        paymentResult,
        processingFee,
        credentialName: credential.name,
        nowIso,
      }),
      activeStep: 2,
      error: null,
    };
  } catch (error) {
    return {
      receiptData: buildPaymentCheckoutReceipt({
        paymentResult,
        processingFee,
        credentialName: credential.name,
        nowIso,
        warning: 'Application submission pending - you will receive a confirmation email',
      }),
      activeStep: 2,
      error: null,
    };
  }
}

export async function processPaymentCheckout({
  processingFee,
  billingInfo,
  credential,
  user,
  processPayment,
  submitCheckoutApplication,
  nowIso = new Date().toISOString(),
}) {
  if (processingFee === 0) {
    return submitPaymentCheckoutApplication({
      submitCheckoutApplication,
      credential,
      processingFee,
      billingInfo,
      paymentResult: null,
      nowIso,
    });
  }

  const paymentResult = await processPayment(
    processingFee,
    'USD',
    buildPaymentCheckoutMetadata({ credential, user, billingInfo })
  );

  if (!paymentResult?.success) {
    throw new Error(paymentResult?.error || 'Payment failed');
  }

  return submitPaymentCheckoutApplication({
    submitCheckoutApplication,
    credential,
    processingFee,
    billingInfo,
    paymentResult,
    nowIso,
  });
}
