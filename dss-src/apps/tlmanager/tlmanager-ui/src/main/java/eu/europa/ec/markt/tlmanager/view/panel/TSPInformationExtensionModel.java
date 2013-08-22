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

package eu.europa.ec.markt.tlmanager.view.panel;

/**
 * A model for the values to define a 'TSPInformationExtensions', which is an ExtensionsListType
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class TSPInformationExtensionModel implements ContentModel {

    private boolean critical;
    private String extension = "";

    /**
     * Instantiates a new TSP information extension model.
     */
    public TSPInformationExtensionModel() {
    }

    /**
     * Instantiates a new TSP information extension model.
     * 
     * @param critical the criticality state
     * @param extension the oid value
     */
    public TSPInformationExtensionModel(boolean critical, String extension) {
        this.critical = critical;
        this.extension = extension;
    }

    /**
     * Instantiates a new TSP information extension model.
     * 
     * @param tspInformationExtensionModel the TSP information extension model
     */
    public TSPInformationExtensionModel(TSPInformationExtensionModel tspInformationExtensionModel) {
        this.critical = tspInformationExtensionModel.isCritical();
        this.extension = tspInformationExtensionModel.getExtension();
    }

    /**
     * {@inheritDoc} The critical state is not considered to be valuable content.
     */
    @Override
    public boolean isEmpty() {
        if (!extension.isEmpty()) {
            return false;
        }
        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void clear() {
        setCritical(false);
        setExtension("");
    }

    /**
     * @return the critical
     */
    public boolean isCritical() {
        return critical;
    }

    /**
     * @param critical the critical to set
     */
    public void setCritical(boolean critical) {
        this.critical = critical;
    }

    /**
     * @return the extension
     */
    public String getExtension() {
        return extension;
    }

    /**
     * @param extension the extension to set
     */
    public void setExtension(String extension) {
        this.extension = extension;
    }
}