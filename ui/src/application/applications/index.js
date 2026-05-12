export {
  buildApplicantProfileData,
  buildAutoApplyContext,
  buildStandardApplicationPayload,
  getCredentialKindFlags,
  getOneClickSummaryFields,
  groupFieldsIntoSteps,
  normalizeCredentialConfigInput,
  normalizeTemplateToFormConfig,
  validateApplicationStep,
} from './applicationFlow';

export {
  autoApplyForCredential,
  ensureApplicantProfileForApplication,
  loadCredentialApplicationConfig,
  resolveApplicantIdForApplication,
  submitCredentialApplication,
} from './applicationFormUseCases';

// Moved to @marty/subscriptions. Re-exported here for backward compatibility during migration.
export {
  buildPaymentCheckoutInitialBillingInfo,
  buildPaymentCheckoutMetadata,
  buildPaymentCheckoutReceipt,
  buildPaymentCheckoutSubmissionPayload,
  initializePaymentCheckout,
  processPaymentCheckout,
  submitPaymentCheckoutApplication,
  updatePaymentCheckoutBillingInfo,
  validatePaymentCheckoutBilling,
} from '@marty/subscriptions';

export {
  buildCredentialApplicationNavigationState,
  resolveCredentialApplicationPath,
  extractApplicationStatusInfo,
  extractExistingApplicationIds,
  filterCredentialCatalogItems,
  getCredentialCatalogCategories,
  loadCredentialCatalogItems,
  loadExistingCredentialApplications,
  mapCredentialTemplateToCatalogItem,
} from './credentialCatalog';

export {
  formatMyDocumentDate,
  getMyDocumentDisplayName,
  getMyDocumentExpiryDate,
  getMyDocumentIssueDate,
  getMyDocumentNationality,
  getMyDocumentStatus,
  isMyDocumentExpired,
  isMyDocumentExpiringSoon,
  loadMyDocuments,
} from './myDocuments';

export {
  MY_APPLICATION_STATUS_COLORS,
  MY_APPLICATION_STATUS_LABELS,
  buildMyApplicationEditNavigation,
  canAddMyApplicationToWallet,
  canEditMyApplication,
  formatMyApplicationDate,
  formatMyApplicationId,
  getMyApplicationStatusPresentation,
  loadMyApplications,
  normalizeMyApplicationStatus,
} from './myApplications';

export {
  buildWalletRegistryMaps,
  createWalletOfferDialogState,
  enrichWalletOfferForRouting,
  getWalletOfferDialogError,
  getWalletOfferPrimaryUri,
  loadWalletOfferDialog,
  resetWalletOfferDialogState,
  resolveWalletOfferDialogLoad,
  resolveWalletOfferRoutingWalletIds,
  startWalletOfferDialogLoad,
} from './walletOfferDialogUseCases';

export {
  mergeApplicantsIntoApplications,
} from './orgApplicationsFlow';

export {
  loadOrganizationApplications,
} from './orgApplicationsUseCases';
