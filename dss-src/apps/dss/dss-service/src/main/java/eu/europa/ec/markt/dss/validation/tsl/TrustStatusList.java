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

package eu.europa.ec.markt.dss.validation.tsl;

import eu.europa.ec.markt.tsl.jaxb.tsl.OtherTSLPointerType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TrustStatusListType;

import java.util.ArrayList;
import java.util.List;

/**
 * 
 * Represents a Trusted List
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

class TrustStatusList {

    private TrustStatusListType trustStatusListType;
    
    private boolean wellSigned = false;

    /**
     * 
     * The default constructor for TrustStatusList.
     * 
     * @param trustStatusListType
     */
    public TrustStatusList(TrustStatusListType trustStatusListType) {
        this.trustStatusListType = trustStatusListType;
    }
    
    /**
     * @param wellSigned the wellSigned to set
     */
    public void setWellSigned(boolean wellSigned) {
        this.wellSigned = wellSigned;
    }
    
    /**
     * @return the wellSigned
     */
    public boolean isWellSigned() {
        return wellSigned;
    }

    /**
     * Return the list of provider in this trusted list
     * 
     * @return
     */
    public List<TrustServiceProvider> getTrustServicesProvider() {
        List<TrustServiceProvider> list = new ArrayList<TrustServiceProvider>();
        if (trustStatusListType.getTrustServiceProviderList() != null
                && trustStatusListType.getTrustServiceProviderList().getTrustServiceProvider() != null) {
            for (TSPType tsp : trustStatusListType.getTrustServiceProviderList().getTrustServiceProvider()) {
                list.add(new TrustServiceProvider(tsp));
            }
        }
        return list;
    }

    /**
     * Return pointer to other TSL (with mime/type = application/vnd.etsi.tsl+xml)
     * 
     * @return
     */
    public List<PointerToOtherTSL> getOtherTSLPointers() {
        List<PointerToOtherTSL> list = new ArrayList<PointerToOtherTSL>();

        if (trustStatusListType.getSchemeInformation().getPointersToOtherTSL() != null) {
            for (OtherTSLPointerType p : trustStatusListType.getSchemeInformation().getPointersToOtherTSL()
                    .getOtherTSLPointer()) {
                PointerToOtherTSL pointer = new PointerToOtherTSL(p);
                if (pointer.getMimeType().equals("application/vnd.etsi.tsl+xml")) {
                    list.add(pointer);
                }
            }
        }
        return list;
    }

}
