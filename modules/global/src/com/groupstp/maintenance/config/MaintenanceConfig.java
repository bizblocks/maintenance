package com.groupstp.maintenance.config;

import com.haulmont.cuba.core.config.Config;
import com.haulmont.cuba.core.config.Property;
import com.haulmont.cuba.core.config.Source;
import com.haulmont.cuba.core.config.SourceType;
import com.haulmont.cuba.core.config.defaults.Default;
import com.haulmont.cuba.core.config.defaults.DefaultBoolean;
import com.haulmont.cuba.core.config.type.Factory;
import com.haulmont.cuba.core.config.type.UuidTypeFactory;

import java.util.UUID;

/**
 * Maintenance configuration settings
 *
 * @author adiatullin
 */
@Source(type = SourceType.DATABASE)
public interface MaintenanceConfig extends Config {

    /**
     * @return is maintenance mode enabled or not
     */
    @Property("maintenance.enabled")
    @DefaultBoolean(false)
    Boolean getEnabled();

    void setEnabled(Boolean value);

    /**
     * @return login page open url parameter
     */
    @Property("maintenance.loginParameterName")
    @Default("login")
    String getLoginParameterName();

    void setLoginParameterName(String value);

    /**
     * @return maintenance page body
     */
    @Property("maintenance.page")
    @Default("<!DOCTYPE html>\n" +
            "<html lang=\"en\">\n" +
            "<head>\n" +
            "    <meta charset=\"UTF-8\">\n" +
            "    <title>Техническое обслуживание</title>\n" +
            "</head>\n" +
            "<body>\n" +
            "   <center><p>Извините, сервер находится на обслуживании.</p></center>\n" +
            "</body>\n" +
            "</html>")
    String getMaintenancePage();

    void setMaintenancePage(String value);

    /**
     * @return acceptable user role who can access to system in maintenance mode
     */
    @Property("maintenance.accessUserRole")
    @Factory(factory = UuidTypeFactory.class)
    UUID getAccessUserRole();

    void setAccessUserRole(UUID userRole);
}
