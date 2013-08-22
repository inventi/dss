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

import javax.swing.JPanel;

/**
 * A base descriptor class used to reference a Component panel for the Wizard, as well as provide general rules as to
 * how the panel should behave.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public abstract class AbstractWizardPanel extends JPanel implements WizardPage {

    private static final long serialVersionUID = 7026600435866199431L;
    
    private WizardApplet wizard;

    @Override
    public void setWizard(WizardApplet w) {
        wizard = w;
    }

    /**
     * Returns a reference to the Wizard component.
     * 
     * @return The Wizard class hosting this descriptor.
     */
    public final WizardApplet getWizard() {
        return wizard;
    }

    @Override
    public abstract Object getNextPanelDescriptor();

    @Override
    public abstract Object getBackPanelDescriptor();

    @Override
    public void aboutToDisplayPanel() throws Exception {

    }

    @Override
    public void displayingPanel() {

    }

    @Override
    public void aboutToHidePanel() {

    }

    @Override
    public boolean skipPanel() {
        return false;
    }
}
