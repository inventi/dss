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

package eu.europa.ec.markt.dss.validation.report;

import eu.europa.ec.markt.dss.validation.AdvancedSignature;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * Validation information for level BES
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class SignatureLevelBES extends SignatureLevel {

    private X509Certificate signingCertificate;
    private Result signingCertRefVerification;
    private SignatureVerification[] counterSignaturesVerification;
    private List<TimestampVerificationResult> timestampsVerification;
    private List<X509Certificate> certificates;
    private Date signingTime;
    private String location;
    private String[] claimedSignerRole;
    private String contentType;

    /**
     * The default constructor for SignatureLevelBES.
     * 
     * @param name
     * @param signature
     * @param levelReached
     */
    public SignatureLevelBES(Result levelReached, AdvancedSignature signature,
            Result signingCertificateVerification, SignatureVerification[] counterSignatureVerification,
            List<TimestampVerificationResult> timestampsVerification) {
        super(levelReached);

        this.signingCertRefVerification = signingCertificateVerification;
        this.counterSignaturesVerification = counterSignatureVerification;
        this.timestampsVerification = timestampsVerification;

        if (signature != null) {
            certificates = signature.getCertificates();
            signingCertificate = signature.getSigningCertificate();
            signingTime = signature.getSigningTime();
            location = signature.getLocation();
            claimedSignerRole = signature.getClaimedSignerRoles();
            contentType = signature.getContentType();
        }
    }

    /**
     * @return the signingCertificateVerification
     */
    public Result getSigningCertRefVerification() {
        return signingCertRefVerification;
    }

    /**
     * @return the counterSignaturesVerification
     */
    public SignatureVerification[] getCounterSignaturesVerification() {
        return counterSignaturesVerification;
    }

    /**
     * @return the timestampsVerification
     */
    public List<TimestampVerificationResult> getTimestampsVerification() {
        return timestampsVerification;
    }

    /* Delegate methods for the provided AdvancedSignature */

    /**
     * @return
     * @see eu.europa.ec.markt.dss.validation.AdvancedSignature#getCertificates()
     */
    public List<X509Certificate> getCertificates() {
        return certificates;
    }

    /**
     * @return
     * @see eu.europa.ec.markt.dss.validation.AdvancedSignature#getLocation()
     */
    public String getLocation() {
        return location;
    }

    /**
     * @return
     * @see eu.europa.ec.markt.dss.validation.AdvancedSignature#getContentType()
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * @return
     * @see eu.europa.ec.markt.dss.validation.AdvancedSignature#getClaimedSignerRoles()
     */
    public String[] getClaimedSignerRoles() {
        return claimedSignerRole;
    }

    /**
     * 
     * @return
     */
    public X509Certificate getSigningCertificate() {
        return signingCertificate;
    }

    /**
     * The signing time of this signature
     * 
     * @return
     */
    public Date getSigningTime() {
        return signingTime;
    }

}
