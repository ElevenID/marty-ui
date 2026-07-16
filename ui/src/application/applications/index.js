export {
  buildApplicantProfileData,
  buildAutoApplyFormData,
  canAutoApplyApplicationTemplate,
  buildStandardApplicationPayload,
  getCredentialKindFlags,
  getOneClickSummaryFields,
  groupFieldsIntoSteps,
  normalizeApplicationTemplateToFormConfig,
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
  scopeCredentialCatalogItemsForCanvasLaunch,
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
  ANY_OID4VCI_WALLET_ID,
  MARTY_AUTHENTICATOR_WALLET_ID,
  buildWalletRegistryMaps,
  buildClaimWalletOptions,
  createWalletOfferDialogState,
  enrichWalletOfferForRouting,
  getWalletOfferDialogError,
  getWalletOfferPrimaryUri,
  loadWalletOfferDialog,
  resetWalletOfferDialogState,
  resolveClaimWalletDeliveryDestinationId,
  resolveClaimWalletSelection,
  resolveWalletOfferDialogLoad,
  resolveWalletOfferRoutingWalletIds,
  selectedClaimWalletIds,
  startWalletOfferDialogLoad,
  walletSupportsBrowserLaunch,
  walletSupportsOid4vci,
} from './walletOfferDialogUseCases';

export {
  mergeApplicantsIntoApplications,
} from './orgApplicationsFlow';

export {
  loadOrganizationApplications,
} from './orgApplicationsUseCases';
