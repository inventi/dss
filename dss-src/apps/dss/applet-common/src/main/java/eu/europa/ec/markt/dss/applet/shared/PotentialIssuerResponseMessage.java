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

package eu.europa.ec.markt.dss.applet.shared;

import java.io.Serializable;

/**
 * Contains an array of every potential issuers corresponding to a X500Principal
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class PotentialIssuerResponseMessage implements Serializable {

    private static final long serialVersionUID = 1L;

    private byte[][] potentialIssuers;

    private String[] certificateContext;

    private Serializable[] certificateContextInfo;

    /**
     * Get the array of X509Certificate for each potential issuer
     * 
     * @return
     */
    public byte[][] getPotentialIssuers() {
        return potentialIssuers;
    }

    /**
     * Set the array of X509Certificate that contains all the potential issuers.
     * 
     * @param potentialIssuers
     */
    public void setPotentialIssuers(byte[][] potentialIssuers) {
        this.potentialIssuers = potentialIssuers;
    }

    /**
     * Get the array of source for each potential issuer
     * 
     * @return
     */
    public String[] getCertificateContext() {
        return certificateContext;
    }

    /**
     * Set the array of source for each potential issuer
     * 
     * @param certificateContext
     */
    public void setCertificateContext(String[] certificateContext) {
        this.certificateContext = certificateContext;
    }

    /**
     * Get information about the context from which the certificate is fetched
     * 
     * @return
     */
    public Serializable[] getCertificateContextInfo() {
        return certificateContextInfo;
    }

    /**
     * Set information about the context from which the certificate is fetched
     * 
     * @param certificateContextInfo
     */
    public void setCertificateContextInfo(Serializable[] certificateContextInfo) {
        this.certificateContextInfo = certificateContextInfo;
    }

}
