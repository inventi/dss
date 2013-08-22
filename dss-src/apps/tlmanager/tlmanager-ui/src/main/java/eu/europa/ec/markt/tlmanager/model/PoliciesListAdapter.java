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

package eu.europa.ec.markt.tlmanager.model;

import eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueModel;
import eu.europa.ec.markt.tsl.jaxb.ecc.PoliciesListType;

import java.util.List;

/**
 * 
 * // assume only one PoliciesSet for now - Ref: PolicySet-SingUse -> adapter not needed
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class PoliciesListAdapter implements MultivalueModel {

    /**
     * The default constructor for PoliciesListAdapter.
     * 
     * @param source
     */
    public PoliciesListAdapter(PoliciesListType source) {
    }

    /** {@inheritDoc} */
    @Override
    public Object getValue(String key) {
        return null;
    }

    /** {@inheritDoc} */
    @Override
    public List<String> getKeys() {
        return null;
    }

    /** {@inheritDoc} */
    @Override
    public List<Object> getValues() {
        return null;
    }

    /** {@inheritDoc} */
    @Override
    public void setValue(String key, Object value) {
    }

    /** {@inheritDoc} */
    @Override
    public String getInitialValueKey() {
        return null;
    }

    /**
     * @return
     */
    public PoliciesListType getPolicies() {
        return null;
    }
}