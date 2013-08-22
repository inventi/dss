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

/**
 * A page in the wizard
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public interface WizardPage {

    /**
     * Returns the unique Object-based identifier for this panel descriptor.
     * 
     * @return The Object-based identifier
     */
    public abstract Object getPanelDescriptorIdentifier();

    /**
     * Set the wizard that contains this page
     * 
     * @param wizard
     */
    void setWizard(WizardApplet wizard);

    /**
     * Override this class to provide the Object-based identifier of the panel that the user should traverse to when the
     * Next button is pressed. Note that this method is only called when the button is actually pressed, so that the
     * panel can change the next panel's identifier dynamically at runtime if necessary. Return null if the button
     * should be disabled. Return FinishIdentfier if the button text should change to 'Finish' and the dialog should
     * end.
     * 
     * @return Object-based identifier.
     */
    public abstract Object getNextPanelDescriptor();

    /**
     * Override this class to provide the Object-based identifier of the panel that the user should traverse to when the
     * Back button is pressed. Note that this method is only called when the button is actually pressed, so that the
     * panel can change the previous panel's identifier dynamically at runtime if necessary. Return null if the button
     * should be disabled.
     * 
     * @return Object-based identifier
     */
    public abstract Object getBackPanelDescriptor();

    /**
     * Override this method to provide functionality that will be performed just before the panel is to be displayed.
     */
    public abstract void aboutToDisplayPanel() throws Exception;

    /**
     * Override this method to perform functionality when the panel itself is displayed.
     */
    public abstract void displayingPanel();

    /**
     * Override this method to perform functionality just before the panel is to be hidden.
     */
    public abstract void aboutToHidePanel();

    /**
     * Return true if the panel must be skipped
     * 
     * @return
     */
    public abstract boolean skipPanel();

}