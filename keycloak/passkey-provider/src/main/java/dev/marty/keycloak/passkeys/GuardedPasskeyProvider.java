package dev.marty.keycloak.passkeys;

import java.util.HashSet;
import java.util.Set;

import com.webauthn4j.converter.util.ObjectConverter;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.keycloak.authentication.authenticators.browser.WebAuthnMetadataService;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowBindings;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.jpa.entities.CredentialEntity;
import org.keycloak.models.utils.AuthenticationFlowResolver;

/**
 * Native Account API and delete_credential AIA both consult this metadata before
 * deletion. Administrator deletion remains an explicit privileged operation.
 */
public final class GuardedPasskeyProvider extends WebAuthnPasswordlessCredentialProvider {
    public GuardedPasskeyProvider(KeycloakSession session, WebAuthnMetadataService metadata, ObjectConverter converter) {
        super(session, metadata, converter);
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext context) {
        RealmModel realm = getKeycloakSession().getContext().getRealm();
        if (!Boolean.TRUE.equals(realm.getWebAuthnPolicyPasswordless().isPasskeysEnabled())) {
            return super.getCredentialTypeMetadata(context);
        }
        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.PASSWORDLESS)
                .displayName("webauthn-passwordless-display-name")
                .helpText("webauthn-passwordless-help-text")
                .iconCssClass("kcAuthenticatorWebAuthnPasswordlessClass")
                .createAction(WebAuthnPasswordlessRegisterFactory.PROVIDER_ID)
                .removeable(hasRemainingMethod(realm, context.getUser()))
                .build(getKeycloakSession());
    }

    private boolean hasRemainingMethod(RealmModel realm, UserModel user) {
        if (user == null) return false;
        JpaConnectionProvider connection = getKeycloakSession().getProvider(JpaConnectionProvider.class);
        if (connection == null) return false;
        EntityManager manager = connection.getEntityManager();
        // Serialize decisions and native deletions until the same Keycloak
        // transaction commits. A JVM-local mutex would not protect a cluster.
        UserEntity entity = manager.find(UserEntity.class, user.getId(), LockModeType.PESSIMISTIC_WRITE);
        if (entity == null || !realm.getId().equals(entity.getRealmId())) return false;
        // Query committed credential rows after the lock, not a cached UserModel.
        var types = manager.createQuery("select c from CredentialEntity c where c.user = :user", CredentialEntity.class)
                .setParameter("user", entity).setLockMode(LockModeType.PESSIMISTIC_READ)
                .getResultList().stream().map(CredentialEntity::getType).toList();
        long passkeys = types.stream().filter(getType()::equals).count();
        AuthenticationFlowModel flow = getKeycloakSession().getContext().getClient() == null ? null
                : AuthenticationFlowResolver.resolveBindingOverrideFlowForClient(
                        getKeycloakSession().getContext().getClient(), AuthenticationFlowBindings.BROWSER_BINDING);
        if (flow == null) flow = realm.getBrowserFlow();
        if (passkeys > 1 && authenticatorEnabled(realm, flow, new HashSet<>(), Set.of(
                "auth-username-password-form", "auth-username-form", "webauthn-authenticator-passwordless"))) return true;
        return types.contains("password") && authenticatorEnabled(realm, flow, new HashSet<>(),
                Set.of("auth-username-password-form", "auth-password-form"));
    }

    private boolean authenticatorEnabled(RealmModel realm, AuthenticationFlowModel flow,
                                         Set<String> visited, Set<String> authenticators) {
        if (flow == null || !visited.add(flow.getId())) return false;
        return realm.getAuthenticationExecutionsStream(flow.getId()).anyMatch(execution -> {
            if (execution.getRequirement() == AuthenticationExecutionModel.Requirement.DISABLED) return false;
            if (execution.isAuthenticatorFlow()) {
                return authenticatorEnabled(realm, realm.getAuthenticationFlowById(execution.getFlowId()), visited, authenticators);
            }
            return authenticators.contains(execution.getAuthenticator());
        });
    }
}
