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

import java.awt.event.ActionListener;

import javax.swing.JComponent;

/**
 * This class is responsible for reacting to events generated by pushing any of the three buttons, 'Next', 'Previous',
 * and 'Cancel.' Based on what button is pressed, the controller will update the model to show a new panel and reset the
 * state of the buttons as necessary.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class WizardController implements ActionListener {

    private Object FINISHED_ID = new Object();

    private WizardApplet wizard;

    /**
     * This constructor accepts a reference to the Wizard component that created it, which it uses to update the button
     * components and access the WizardModel.
     * 
     * @param w A callback to the Wizard component that created this controller.
     */
    public WizardController(WizardApplet w) {
        wizard = w;
    }

    /**
     * Set the last page id of the wizard
     * 
     * @param finishedId
     */
    public void setFinishedId(Object finishedId) {
        FINISHED_ID = finishedId;
    }

    /**
     * Calling method for the action listener interface. This class listens for actions performed by the buttons in the
     * Wizard class, and calls methods below to determine the correct course of action.
     * 
     * @param evt The ActionEvent that occurred.
     */
    public void actionPerformed(java.awt.event.ActionEvent evt) {

        if (evt.getActionCommand().equals(WizardApplet.CANCEL_BUTTON_ACTION_COMMAND)) {
            cancelButtonPressed();
        } else if (evt.getActionCommand().equals(WizardApplet.BACK_BUTTON_ACTION_COMMAND)) {
            backButtonPressed();
        } else if (evt.getActionCommand().equals(WizardApplet.NEXT_BUTTON_ACTION_COMMAND)) {
            ((JComponent) evt.getSource()).setEnabled(false);
            try {
                nextButtonPressed();
            } catch (RuntimeException ex) {
                throw ex;
            } finally {
                ((JComponent) evt.getSource()).setEnabled(true);
            }
        }

    }

    private void cancelButtonPressed() {
        wizard.setCurrentPanel(wizard.getInitialPanel(), false);
    }

    private void nextButtonPressed() {

        WizardModel model = wizard.getModel();
        WizardPage descriptor = model.getCurrentPanelDescriptor();

        // If it is a finishable panel, close down the dialog. Otherwise,
        // get the ID that the current panel identifies as the next panel,
        // and display it.

        Object nextPanelDescriptor = descriptor.getNextPanelDescriptor();

        if (nextPanelDescriptor != null) {
            wizard.setCurrentPanel(nextPanelDescriptor, true);
        }

    }

    private void backButtonPressed() {

        WizardModel model = wizard.getModel();
        WizardPage descriptor = model.getCurrentPanelDescriptor();

        // Get the descriptor that the current panel identifies as the previous
        // panel, and display it.

        Object backPanelDescriptor = descriptor.getBackPanelDescriptor();
        wizard.setCurrentPanel(backPanelDescriptor, false);

    }

    void resetButtonsToPanelRules() {

        // Reset the buttons to support the original panel rules,
        // including whether the next or back buttons are enabled or
        // disabled, or if the panel is finishable.

        WizardModel model = wizard.getModel();
        WizardPage descriptor = model.getCurrentPanelDescriptor();

        model.setCancelButtonText(WizardApplet.CANCEL_TEXT);
        model.setCancelButtonIcon(WizardApplet.CANCEL_ICON);

        // If the panel in question has another panel behind it, enable
        // the back button. Otherwise, disable it.

        model.setBackButtonText(WizardApplet.BACK_TEXT);
        model.setBackButtonIcon(WizardApplet.BACK_ICON);

        if (descriptor.getBackPanelDescriptor() != null) {
            model.setBackButtonEnabled(Boolean.TRUE);
        } else {
            model.setBackButtonEnabled(Boolean.FALSE);
        }

        // If the panel in question has one or more panels in front of it,
        // enable the next button. Otherwise, disable it.

        if (descriptor.getNextPanelDescriptor() != null) {
            model.setNextFinishButtonEnabled(Boolean.TRUE);
        } else { 
            model.setNextFinishButtonEnabled(Boolean.FALSE);
        }

        // If the panel in question is the last panel in the series, change
        // the Next button to Finish. Otherwise, set the text back to Next.

        if (FINISHED_ID.equals(descriptor.getNextPanelDescriptor())) {
            model.setNextFinishButtonText(WizardApplet.FINISH_TEXT);
            model.setNextFinishButtonIcon(WizardApplet.FINISH_ICON);
        } else {
            model.setNextFinishButtonText(WizardApplet.NEXT_TEXT);
            model.setNextFinishButtonIcon(WizardApplet.NEXT_ICON);
        }

    }

}
