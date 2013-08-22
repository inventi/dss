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

package eu.europa.ec.markt.dss.validation;

import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * 
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class CertificateStatus {

    private X509Certificate certificate;

    private X509Certificate issuerCertificate;

    private CertificateValidity validity;

    private Object statusSource;

    private ValidatorSourceType statusSourceType;

    private Date revocationObjectIssuingTime;

    private Date revocationDate;

    private Date validationDate;

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "CertificateStatus[The certificate of '"
                + (certificate != null ? certificate.getSubjectDN() : "<<!!null!!>>") + "' is "
                + (validity != null ? validity.toString() : "<<!!null!!>>") + " at the date " + validationDate
                + " according to " + (statusSourceType != null ? statusSourceType.toString() : "<<!!null!!>>") + "]";
    }

    /**
     * Get the certificate for which the status is relevant
     * 
     * @return
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Set the certificate for which the statis is relevant
     * 
     * @param certificate
     */
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Get the issuer certificate
     * 
     * @return
     */
    public X509Certificate getIssuerCertificate() {
        return issuerCertificate;
    }

    /**
     * Set the issuer certificate
     * 
     * @param issuerCertificate
     */
    public void setIssuerCertificate(X509Certificate issuerCertificate) {
        this.issuerCertificate = issuerCertificate;
    }

    /**
     * Data from which the status is coming
     * 
     * @return
     */
    public Object getStatusSource() {
        return statusSource;
    }

    /**
     * Data from which the status is coming
     * 
     * @param statusSource
     */
    public void setStatusSource(Object statusSource) {
        this.statusSource = statusSource;
    }

    /**
     * Type of source from which the status is coming
     * 
     * @return
     */
    public ValidatorSourceType getStatusSourceType() {
        return statusSourceType;
    }

    /**
     * Type of source from which the status is coming
     * 
     * @param statusSourceType
     */
    public void setStatusSourceType(ValidatorSourceType statusSourceType) {
        this.statusSourceType = statusSourceType;
    }

    /**
     * Date when the validation was performed
     * 
     * @return
     */
    public Date getValidationDate() {
        return validationDate;
    }

    /**
     * Date when the validation was performed
     * 
     * @param validationDate
     */
    public void setValidationDate(Date validationDate) {
        this.validationDate = validationDate;
    }

    /**
     * @return the revocationObjectIssuingTime
     */
    public Date getRevocationObjectIssuingTime() {
        return revocationObjectIssuingTime;
    }

    /**
     * @param revocationObjectIssuingTime the revocationObjectIssuingTime to set
     */
    public void setRevocationObjectIssuingTime(Date revocationObjectIssuingTime) {
        this.revocationObjectIssuingTime = revocationObjectIssuingTime;
    }

    /**
     * Result of the validity check
     * 
     * @return
     */
    public CertificateValidity getValidity() {
        return validity;
    }

    /**
     * Result of the validity check
     * 
     * @param validity
     */
    public void setValidity(CertificateValidity validity) {
        this.validity = validity;
    }

    /**
     * @return the revocationDate
     */
    public Date getRevocationDate() {
        return revocationDate;
    }

    /**
     * @param revocationDate the revocationDate to set
     */
    public void setRevocationDate(Date revocationDate) {
        this.revocationDate = revocationDate;
    }
}
