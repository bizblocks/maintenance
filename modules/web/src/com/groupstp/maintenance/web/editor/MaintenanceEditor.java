package com.groupstp.maintenance.web.editor;

import com.groupstp.maintenance.config.MaintenanceConfig;
import com.haulmont.cuba.core.global.DataManager;
import com.haulmont.cuba.core.global.View;
import com.haulmont.cuba.gui.components.*;
import com.haulmont.cuba.gui.xml.layout.ComponentsFactory;
import com.haulmont.cuba.security.entity.Role;
import org.apache.commons.lang.StringUtils;

import javax.annotation.Nullable;
import javax.inject.Inject;
import java.util.Map;
import java.util.UUID;

/**
 * Maintenance settings editor screen
 *
 * @author adiatullin
 */
public class MaintenanceEditor extends AbstractWindow {

    @Inject
    protected ComponentsFactory componentsFactory;
    @Inject
    protected DataManager dataManager;

    @Inject
    protected MaintenanceConfig config;

    @Inject
    protected CheckBox enableChb;
    @Inject
    protected TextField loginParameterNameField;
    @Inject
    protected LookupField userRoleField;
    @Inject
    protected TabSheet pageEditorTabSheet;
    @Inject
    protected SourceCodeEditor pageEditorHtml;
    @Inject
    protected RichTextArea pageEditorRich;
    @Inject
    protected ScrollBoxLayout previewBox;


    @Override
    public void init(Map<String, Object> params) {
        super.init(params);

        initData();
        initListeners();
    }

    protected void initData() {
        enableChb.setValue(config.getEnabled());
        loginParameterNameField.setValue(config.getLoginParameterName());
        userRoleField.setValue(getUserRole(config.getAccessUserRole()));

        String page = config.getMaintenancePage();
        pageEditorHtml.setValue(page);
        pageEditorRich.setValue(page);
        showPreview(page);

        pageEditorTabSheet.setSelectedTab(isPureHtml(page) ? "html" : "rich");
    }

    protected boolean isPureHtml(String page) {
        page = page.toLowerCase();
        return page.startsWith("<!doctype") || page.startsWith("<html");
    }

    protected void initListeners() {
        pageEditorHtml.addValueChangeListener(e -> showPreview(pageEditorHtml.getValue()));
        pageEditorRich.addValueChangeListener(e -> showPreview(pageEditorRich.getValue()));
        pageEditorTabSheet.addSelectedTabChangeListener(e ->
                showPreview("html".equalsIgnoreCase(e.getSelectedTab().getName()) ? pageEditorHtml.getValue() : pageEditorRich.getValue())
        );
    }

    protected void showPreview(String value) {
        previewBox.removeAll();

        HtmlBoxLayout layout = componentsFactory.createComponent(HtmlBoxLayout.class);
        layout.setWidth("100%");
        layout.setTemplateContents(value);

        previewBox.add(layout);
    }

    public void onOk() {
        if (validateAll()) {
            if (StringUtils.isBlank(loginParameterNameField.getValue())) {
                showNotification(getMessage("maintenanceEditor.warning"), getMessage("maintenanceEditor.error.emptyLoginParameterName"), NotificationType.TRAY);
                loginParameterNameField.requestFocus();
                return;
            }
            Field field = "html".equalsIgnoreCase(pageEditorTabSheet.getSelectedTab().getName()) ? pageEditorHtml : pageEditorRich;
            if (StringUtils.isBlank(field.getValue())) {
                showNotification(getMessage("maintenanceEditor.warning"), getMessage("maintenanceEditor.error.emptyMaintenancePage"), NotificationType.TRAY);
                field.requestFocus();
                return;
            }

            config.setEnabled(enableChb.isChecked());
            config.setLoginParameterName(loginParameterNameField.getValue());
            config.setAccessUserRole(userRoleField.getValue() == null ? null : ((Role) userRoleField.getValue()).getId());
            config.setMaintenancePage(field.getValue());

            close(COMMIT_ACTION_ID, true);
        }
    }

    public void onCancel() {
        close(CLOSE_ACTION_ID, true);
    }

    @Nullable
    protected Role getUserRole(UUID roleId) {
        if (roleId == null) {
            return null;
        }
        return dataManager.load(Role.class)
                .id(roleId)
                .view(View.MINIMAL)
                .optional()
                .orElse(null);
    }
}
