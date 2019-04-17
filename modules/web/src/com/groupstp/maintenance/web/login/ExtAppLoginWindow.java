package com.groupstp.maintenance.web.login;

import com.groupstp.maintenance.config.MaintenanceConfig;
import com.haulmont.cuba.gui.components.BoxLayout;
import com.haulmont.cuba.gui.components.HtmlBoxLayout;
import com.haulmont.cuba.gui.components.Label;
import com.haulmont.cuba.gui.components.ScrollBoxLayout;
import com.haulmont.cuba.gui.executors.BackgroundWorker;
import com.haulmont.cuba.gui.executors.UIAccessor;
import com.haulmont.cuba.gui.xml.layout.ComponentsFactory;
import com.haulmont.cuba.security.auth.Credentials;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.web.app.loginwindow.AppLoginWindow;
import com.vaadin.server.*;
import com.vaadin.ui.UIDetachedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.Map;

/**
 * Extended application login window to support maintenance page
 *
 * @author adiatullin
 */
public class ExtAppLoginWindow extends AppLoginWindow {
    private static final Logger log = LoggerFactory.getLogger(ExtAppLoginWindow.class);

    @Inject
    protected BackgroundWorker backgroundWorker;
    @Inject
    protected ComponentsFactory componentsFactory;

    @Inject
    protected ScrollBoxLayout maintenanceBox;
    @Inject
    protected BoxLayout loginWrapper;
    @Inject
    protected Label poweredByLink;

    @Inject
    protected MaintenanceConfig maintenanceConfig;

    protected UIAccessor uiAccessor;

    protected RequestHandler requestHandler = (RequestHandler) (s, req, res) -> checkMaintenancePage();


    @Override
    public void init(Map<String, Object> params) {
        super.init(params);

        uiAccessor = backgroundWorker.getUIAccessor();
    }

    @Override
    public void ready() {
        super.ready();

        setupMaintenanceRequestHandler();
        checkMaintenancePage();
    }

    protected void setupMaintenanceRequestHandler() {
        VaadinSession.getCurrent().addRequestHandler(requestHandler);
    }

    protected boolean checkMaintenancePage() {
        try {
            uiAccessor.accessSynchronously(() -> {
                boolean showMaintenance = false;
                if (Boolean.TRUE.equals(maintenanceConfig.getEnabled())) {
                    showMaintenance = !VaadinService.getCurrentRequest()
                            .getParameterMap().containsKey(maintenanceConfig.getLoginParameterName());
                }
                if (showMaintenance) {
                    maintenanceBox.removeAll();
                    HtmlBoxLayout layout = componentsFactory.createComponent(HtmlBoxLayout.class);
                    layout.setTemplateContents(maintenanceConfig.getMaintenancePage());
                    layout.setWidth("100%");
                    maintenanceBox.add(layout);
                }
                maintenanceBox.setVisible(showMaintenance);
                loginWrapper.setVisible(!showMaintenance);
                poweredByLink.setVisible(!showMaintenance && webConfig.getLoginDialogPoweredByLinkVisible());
            });
        } catch (UIDetachedException e) {
            log.debug("Ignore to show maintenance page since user session already expired");
            VaadinSession.getCurrent().removeRequestHandler(requestHandler);
        }
        return false;
    }

    @Override
    protected void doLogin(Credentials credentials) throws LoginException {
        super.doLogin(credentials);

        VaadinSession.getCurrent().removeRequestHandler(requestHandler);
    }
}