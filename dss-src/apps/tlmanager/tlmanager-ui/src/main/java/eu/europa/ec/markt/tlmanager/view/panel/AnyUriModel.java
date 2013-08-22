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

import eu.europa.ec.markt.tlmanager.util.Util;

/**
 * A model for the values of any URI
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class AnyUriModel implements ContentModel {

    private String type = Util.DEFAULT_NO_SELECTION_ENTRY;
    private String address = "";

    /**
     * Instantiates a new AnyUriModel.
     */
    public AnyUriModel() {
    }

    /**
     * Instantiates a new AnyUriModel.
     * 
     * @param type the type
     * @param address the address
     */
    public AnyUriModel(String type, String address) {
        this.type = type;
        this.address = address;
    }

    /**
     * Instantiates a new AnyUriModel.
     * 
     * @param anyUriModel the AnyUriModel
     */
    public AnyUriModel(AnyUriModel anyUriModel) {
        this.type = anyUriModel.getType();
        this.address = anyUriModel.getAddress();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isEmpty() {
        if (!type.equals(Util.DEFAULT_NO_SELECTION_ENTRY) || !address.isEmpty()) {
            return false;
        }
        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void clear() {
        setType(Util.DEFAULT_NO_SELECTION_ENTRY);
        setAddress("");
    }

    /**
     * @return the type
     */
    public String getType() {
        return type;
    }

    /**
     * @param type the type to set
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * @return the address
     */
    public String getAddress() {
        return address;
    }

    /**
     * @param address the address to set
     */
    public void setAddress(String address) {
        this.address = address;
    }
}