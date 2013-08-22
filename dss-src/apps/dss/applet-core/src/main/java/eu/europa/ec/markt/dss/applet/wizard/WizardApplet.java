/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.applet.wizard;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Insets;
import java.awt.event.WindowEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.net.URL;
import java.util.MissingResourceException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JApplet;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.border.EmptyBorder;

/**
 * This class implements a basic wizard dialog, where the programmer can insert one or more Components to act as panels.
 * These panels can be navigated through arbitrarily using the 'Next' or 'Back' buttons, or the dialog itself can be
 * closed using the 'Cancel' button. Note that even though the dialog uses a CardLayout manager, the order of the panels
 * is not linear. Each panel determines at runtime what its next and previous panel will be.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class WizardApplet extends JApplet implements PropertyChangeListener {

    private static final Logger LOG = Logger.getLogger(WizardApplet.class.getName());

    private static final long serialVersionUID = 7272613449408050346L;

    /**
     * Indicates that the 'Finish' button was pressed to close the dialog.
     */
    public static final int FINISH_RETURN_CODE = 0;
    /**
     * Indicates that the 'Cancel' button was pressed to close the dialog, or the user pressed the close box in the
     * corner of the window.
     */
    public static final int CANCEL_RETURN_CODE = 1;
    /**
     * Indicates that the dialog closed due to an internal error.
     */
    public static final int ERROR_RETURN_CODE = 2;
    /**
     * The String-based action command for the 'Next' button.
     */
    public static final String NEXT_BUTTON_ACTION_COMMAND = "NextButtonActionCommand";
    /**
     * The String-based action command for the 'Back' button.
     */
    public static final String BACK_BUTTON_ACTION_COMMAND = "BackButtonActionCommand";
    /**
     * The String-based action command for the 'Cancel' button.
     */
    public static final String CANCEL_BUTTON_ACTION_COMMAND = "CancelButtonActionCommand";
    // The i18n text used for the buttons. Loaded from a property resource file.

    public static String BACK_TEXT = getResourceString("BACK");
    public static String NEXT_TEXT = getResourceString("NEXT");
    public static String FINISH_TEXT = getResourceString("FINISH");
    public static String CANCEL_TEXT = getResourceString("CANCEL");

    // The image icons used for the buttons. Filenames are loaded from a
    // property resource file.
    private static String getResourceString(String name) {
        return java.util.ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n").getString(name);
    }


    // The image icons used for the buttons. Filenames are loaded from a property resource file.
    static Icon BACK_ICON;
    static Icon NEXT_ICON;
    static Icon FINISH_ICON;
    static Icon CANCEL_ICON;
    private WizardModel wizardModel;
    private WizardController wizardController;
    private JPanel cardPanel;
    private CardLayout cardLayout;
    private JButton backButton;
    private JButton nextButton;
    private JButton cancelButton;
    private int returnCode;
    private String initialPanel;
    private String errorPanel;
    private WizardSteps stepsProgression;

    /**
     * Set the progression in the current wizard
     * 
     * @param step
     */
    public void setStepsProgression(int step) {
        if (stepsProgression != null) {
            stepsProgression.setCurrentStep(step);
        }
    }

    /**
     * 
     * @param errorPanel
     */
    public void setErrorPanel(String errorPanel) {
        this.errorPanel = errorPanel;
    }

    @Override
    public void init() {

        try {

            BACK_ICON = new ImageIcon((URL) getImage("arrow_left.png"));
            NEXT_ICON = new ImageIcon((URL) getImage("arrow_right.png"));
            CANCEL_ICON = new ImageIcon((URL) getImage("cancel.png"));
            FINISH_ICON = new ImageIcon((URL) getImage("ok.png"));

        } catch (MissingResourceException mre) {
            throw new RuntimeException(mre);
        }

        wizardModel = new WizardModel();
        initComponents();

    }

    /**
     * Returns the current model of the wizard dialog.
     * 
     * @return A WizardModel instance, which serves as the model for the wizard dialog.
     */
    public WizardModel getModel() {
        return wizardModel;
    }

    /**
     * Add a Component as a panel for the wizard dialog by registering its WizardPanelDescriptor object. Each panel is
     * identified by a unique Object-based identifier (often a String), which can be used by the setCurrentPanel()
     * method to display the panel at runtime.
     * 
     * @param panel The WizardPanelDescriptor object which contains helpful information about the panel.
     */
    public void registerWizardPanel(AbstractWizardPanel panel) {

        // Add the incoming panel to our JPanel display that is managed by
        // the CardLayout layout manager.

        cardPanel.add(panel, panel.getPanelDescriptorIdentifier());

        // Set a callback to the current wizard.

        panel.setWizard(this);

        // Place a reference to it in the model.

        wizardModel.registerPanel(panel.getPanelDescriptorIdentifier(), panel);

    }

    /**
     * @param initialPanel the initialPanel to set
     */
    public void setInitialPanel(String initialPanel) {
        this.initialPanel = initialPanel;
    }

    /**
     * @return the initialPanel
     */
    public String getInitialPanel() {
        return initialPanel;
    }

    /**
     * Displays the panel identified by the object passed in. This is the same Object-based identified used when
     * registering the panel.
     * 
     * @param id The Object-based identifier of the panel to be displayed.
     */
    public void setCurrentPanel(final Object id, final boolean skipForward) {

        WaitingGlassPanel waitingGlassPanel = new WaitingGlassPanel();
        waitingGlassPanel.setVisible(true);
        getRootPane().setGlassPane(waitingGlassPanel);
        getRootPane().getGlassPane().setVisible(true);

        SwingWorker worker = new SwingWorker() {
            @Override
            protected Object doInBackground() throws Exception {

                try {
                    WizardPage oldPanelDescriptor = wizardModel.getCurrentPanelDescriptor();
                    if (oldPanelDescriptor != null) {
                        oldPanelDescriptor.aboutToHidePanel();
                    }

                    wizardModel.setCurrentPanel(id);
                    if (wizardModel.getCurrentPanelDescriptor().skipPanel()) {
                        if (skipForward) {
                            setCurrentPanel(wizardModel.getCurrentPanelDescriptor().getNextPanelDescriptor(),
                                    skipForward);
                        } else {
                            setCurrentPanel(wizardModel.getCurrentPanelDescriptor().getBackPanelDescriptor(),
                                    skipForward);
                        }
                    } else {
                        wizardModel.getCurrentPanelDescriptor().aboutToDisplayPanel();
                        cardLayout.show(cardPanel, id.toString());
                        wizardModel.getCurrentPanelDescriptor().displayingPanel();
                        wizardModel.setException(null);

                    }
                } catch (Exception ex) {
                    if (errorPanel != null) {
                        LOG.log(Level.SEVERE, "Error while setting new panel, displaying error panel", ex);
                        wizardModel.setException(ex);
                        setCurrentPanel(errorPanel, skipForward);
                    } else {
                        LOG.log(Level.SEVERE, "Error while setting new panel", ex);
                    }
                } finally {
                    getRootPane().getGlassPane().setVisible(false);
                }
                return null;
            }
        };

        new Thread(worker).start();
    }

    /**
     * Method used to listen for property change events from the model and update the dialog's graphical components as
     * necessary.
     * 
     * @param evt PropertyChangeEvent passed from the model to signal that one of its properties has changed value.
     */
    public void propertyChange(PropertyChangeEvent evt) {

        if (evt.getPropertyName().equals(WizardModel.CURRENT_PANEL_DESCRIPTOR_PROPERTY)) {
            wizardController.resetButtonsToPanelRules();
        } else if (evt.getPropertyName().equals(WizardModel.NEXT_FINISH_BUTTON_TEXT_PROPERTY)) {
            nextButton.setText(evt.getNewValue().toString());
            nextButton.setMnemonic(evt.getNewValue().toString().charAt(0));
        } else if (evt.getPropertyName().equals(WizardModel.BACK_BUTTON_TEXT_PROPERTY)) {
            backButton.setText(evt.getNewValue().toString());
            backButton.setMnemonic(evt.getNewValue().toString().charAt(0));
        } else if (evt.getPropertyName().equals(WizardModel.CANCEL_BUTTON_TEXT_PROPERTY)) {
            cancelButton.setText(evt.getNewValue().toString());
            cancelButton.setMnemonic(evt.getNewValue().toString().charAt(0));
        } else if (evt.getPropertyName().equals(WizardModel.NEXT_FINISH_BUTTON_ENABLED_PROPERTY)) {
            nextButton.setEnabled(((Boolean) evt.getNewValue()).booleanValue());
        } else if (evt.getPropertyName().equals(WizardModel.BACK_BUTTON_ENABLED_PROPERTY)) {
            backButton.setEnabled(((Boolean) evt.getNewValue()).booleanValue());
        } else if (evt.getPropertyName().equals(WizardModel.CANCEL_BUTTON_ENABLED_PROPERTY)) {
            cancelButton.setEnabled(((Boolean) evt.getNewValue()).booleanValue());
        } else if (evt.getPropertyName().equals(WizardModel.NEXT_FINISH_BUTTON_ICON_PROPERTY)) {
            nextButton.setIcon((Icon) evt.getNewValue());
        } else if (evt.getPropertyName().equals(WizardModel.BACK_BUTTON_ICON_PROPERTY)) {
            backButton.setIcon((Icon) evt.getNewValue());
        } else if (evt.getPropertyName().equals(WizardModel.CANCEL_BUTTON_ICON_PROPERTY)) {
            cancelButton.setIcon((Icon) evt.getNewValue());
        }

    }

    /**
     * Retrieves the last return code set by the dialog.
     * 
     * @return An integer that identifies how the dialog was closed. See the *_RETURN_CODE constants of this class for
     *         possible values.
     */
    public int getReturnCode() {
        return returnCode;
    }

    /**
     * Mirrors the WizardModel method of the same name.
     * 
     * @return A boolean indicating if the button is enabled.
     */
    public boolean getBackButtonEnabled() {
        return wizardModel.getBackButtonEnabled().booleanValue();
    }

    /**
     * Mirrors the WizardModel method of the same name.
     * 
     * @param newValue The new enabled status of the button.
     */
    public void setBackButtonEnabled(boolean newValue) {
        wizardModel.setBackButtonEnabled(new Boolean(newValue));
    }

    /**
     * Mirrors the WizardModel method of the same name.
     * 
     * @return A boolean indicating if the button is enabled.
     */
    public boolean getNextFinishButtonEnabled() {
        return wizardModel.getNextFinishButtonEnabled().booleanValue();
    }

    /**
     * Mirrors the WizardModel method of the same name.
     * 
     * @param newValue The new enabled status of the button.
     */
    public void setNextFinishButtonEnabled(boolean newValue) {
        wizardModel.setNextFinishButtonEnabled(new Boolean(newValue));
    }

    /**
     * Mirrors the WizardModel method of the same name.
     * 
     * @return A boolean indicating if the button is enabled.
     */
    public boolean getCancelButtonEnabled() {
        return wizardModel.getCancelButtonEnabled().booleanValue();
    }

    /**
     * Mirrors the WizardModel method of the same name.
     * 
     * @param newValue The new enabled status of the button.
     */
    public void setCancelButtonEnabled(boolean newValue) {
        wizardModel.setCancelButtonEnabled(new Boolean(newValue));
    }

    /**
     * This method initializes the components for the wizard dialog: it creates a JDialog as a CardLayout panel
     * surrounded by a small amount of space on each side, as well as three buttons at the bottom.
     */
    private void initComponents() {

        setBackground(Color.WHITE);

        wizardModel.addPropertyChangeListener(this);
        wizardController = new WizardController(this);

        getContentPane().setLayout(new BorderLayout());
        getContentPane().setBackground(Color.WHITE);

        // Create the outer wizard panel, which is responsible for three buttons:
        // Next, Back, and Cancel. It is also responsible a JPanel above them that
        // uses a CardLayout layout manager to display multiple panels in the
        // same spot.

        JPanel buttonPanel = new JPanel();
        buttonPanel.setBackground(Color.WHITE);

        JSeparator separator = new JSeparator();
        Box buttonBox = new Box(BoxLayout.X_AXIS);

        cardPanel = new JPanel();
        cardPanel.setBorder(new EmptyBorder(new Insets(5, 10, 5, 10)));
        cardPanel.setBackground(Color.WHITE);

        cardLayout = new CardLayout();
        cardPanel.setLayout(cardLayout);

        backButton = new JButton(new ImageIcon("com/nexes/wizard/backIcon.gif"));
        nextButton = new JButton();
        cancelButton = new JButton();

        backButton.setActionCommand(BACK_BUTTON_ACTION_COMMAND);
        backButton.setName("back");
        nextButton.setActionCommand(NEXT_BUTTON_ACTION_COMMAND);
        nextButton.setName("next");
        cancelButton.setActionCommand(CANCEL_BUTTON_ACTION_COMMAND);
        cancelButton.setName("cancel");

        backButton.addActionListener(wizardController);
        nextButton.addActionListener(wizardController);
        cancelButton.addActionListener(wizardController);

        buttonPanel.setLayout(new BorderLayout());
        buttonPanel.add(separator, BorderLayout.NORTH);

        cardPanel.setBorder(new EmptyBorder(new Insets(0, 0, 0, 0)));
        buttonBox.add(backButton);
        buttonBox.add(Box.createHorizontalStrut(10));
        buttonBox.add(nextButton);
        buttonBox.add(Box.createHorizontalStrut(30));
        buttonBox.add(cancelButton);

        // buttonPanel.add(stepsProgression, BorderLayout.CENTER);
        // getContentPane().add(stepsProgression, BorderLayout.NORTH);

        buttonPanel.add(buttonBox, BorderLayout.SOUTH);

        getContentPane().add(buttonPanel, BorderLayout.SOUTH);
        getContentPane().add(cardPanel, BorderLayout.CENTER);

    }

    /**
     * Set the ID of the last page of the wizard
     * 
     * @param id
     */
    public void setFinishedId(Object id) {
        wizardController.setFinishedId(id);
    }

    /**
     * Set the component that display the progression in the wizard
     * 
     * @param stepsProgression
     */
    public void setStepsProgression(WizardSteps stepsProgression) {
        removeStepsProgression();
        this.stepsProgression = stepsProgression;
        getContentPane().add((JPanel) stepsProgression, BorderLayout.NORTH);
    }

    /**
     * Remove the component that display the progression in the wizard
     */
    public void removeStepsProgression() {
        if (stepsProgression != null) {
            getContentPane().remove((JPanel) this.stepsProgression);
            stepsProgression = null;
        }
    }

    private URL getImage(String name) {
        return this.getClass().getResource("/eu/europa/ec/markt/dss/applet/wizard/" + name);
    }

    /**
     * If the user presses the close box on the dialog's window, treat it as a cancel.
     * 
     * @param e The event passed in from AWT.
     */
    public void windowClosing(WindowEvent e) {
        returnCode = CANCEL_RETURN_CODE;
    }
}
