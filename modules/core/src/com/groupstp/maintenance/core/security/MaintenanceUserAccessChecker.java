package com.groupstp.maintenance.core.security;

import com.groupstp.maintenance.config.MaintenanceConfig;
import com.haulmont.cuba.core.EntityManager;
import com.haulmont.cuba.core.Persistence;
import com.haulmont.cuba.core.Transaction;
import com.haulmont.cuba.core.global.Messages;
import com.haulmont.cuba.security.auth.AbstractClientCredentials;
import com.haulmont.cuba.security.auth.AuthenticationDetails;
import com.haulmont.cuba.security.auth.Credentials;
import com.haulmont.cuba.security.auth.checks.AbstractUserAccessChecker;
import com.haulmont.cuba.security.entity.RoleType;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.entity.UserRole;
import com.haulmont.cuba.security.global.LoginException;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Checks if login to system denied since server are in maintenance right now
 *
 * @author adiatullin
 */
@Component("mtnc_MaintenanceUserAccessChecker")
public class MaintenanceUserAccessChecker extends AbstractUserAccessChecker implements Ordered {

    @Inject
    protected Persistence persistence;

    @Inject
    protected MaintenanceConfig config;

    @Inject
    public MaintenanceUserAccessChecker(Messages messages) {
        super(messages);
    }

    @Override
    public int getOrder() {
        return HIGHEST_PLATFORM_PRECEDENCE;
    }

    @Override
    public void check(Credentials credentials, AuthenticationDetails authenticationDetails) throws LoginException {
        User user = authenticationDetails.getSession().getCurrentOrSubstitutedUser();
        if (Boolean.TRUE.equals(config.getEnabled())) {
            if (!isAcceptable(user)) {
                Locale userLocale = null;
                if (credentials instanceof AbstractClientCredentials) {
                    AbstractClientCredentials clientCredentials = (AbstractClientCredentials) credentials;
                    if (clientCredentials.getLocale() != null) {
                        userLocale = clientCredentials.getLocale();
                    }
                }
                if (userLocale == null) {
                    userLocale = messages.getTools().getDefaultLocale();
                }

                throw new LoginException(messages.getMessage(getClass(), "MaintenanceUserAccessChecker.serverUnderMaintenance", userLocale));
            }
        }
    }

    protected boolean isAcceptable(User user) {
        boolean result = false;
        if (user != null) {
            try (Transaction tr = persistence.getTransaction()) {
                EntityManager em = persistence.getEntityManager();
                user = em.merge(user);//to be sure what all user roles are loaded

                if (isAdmin(user) || isSpecialUser(user)) {
                    result = true;
                }

                tr.commit();
            }
        }
        return result;
    }

    protected boolean isAdmin(User user) {
        List<UserRole> userRoles = user.getUserRoles();
        if (!CollectionUtils.isEmpty(userRoles)) {
            for (UserRole ur : userRoles) {
                if (RoleType.SUPER.equals(ur.getRole() == null ? null : ur.getRole().getType())) {
                    return true;
                }
            }
        }
        return false;
    }

    protected boolean isSpecialUser(User user) {
        UUID specialUserRoleId = config.getAccessUserRole();
        if (specialUserRoleId != null) {
            List<UserRole> userRoles = user.getUserRoles();
            if (!CollectionUtils.isEmpty(userRoles)) {
                for (UserRole ur : userRoles) {
                    if (specialUserRoleId.equals(ur.getRole() == null ? null : ur.getRole().getId())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
