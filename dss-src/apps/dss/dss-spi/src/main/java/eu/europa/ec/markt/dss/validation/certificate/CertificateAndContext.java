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

package eu.europa.ec.markt.dss.validation.certificate;

import java.io.Serializable;
import java.security.cert.X509Certificate;

/**
 * A certificate comes from a certain context (Trusted List, CertStore, Signature) and has somes properties
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class CertificateAndContext {

    private X509Certificate certificate;

    private CertificateSourceType certificateSource;

    private Serializable context;

    /**
     * 
     * The default constructor for CertificateAndContext.
     */
    public CertificateAndContext() {
    }

    /**
     * Create a CertificateAndContext wrapping the provided X509Certificate The default constructor for
     * CertificateAndContext.
     * 
     * @param cert
     */
    public CertificateAndContext(X509Certificate cert) {
        this(cert, null);
    }

    /**
     * 
     * The default constructor for CertificateAndContext.
     * 
     * @param cert
     * @param context
     */
    public CertificateAndContext(X509Certificate cert, Serializable context) {
        this.certificate = cert;
        this.context = context;
    }

    /**
     * Get the X509 Certificate
     * 
     * @return
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Set the X509 Certificate
     * 
     * @param certificate
     */
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Get information about the source of the Certificate (TRUSTED_LIST, TRUST_STORE, ...)
     * 
     * @return
     */
    public CertificateSourceType getCertificateSource() {
        return certificateSource;
    }

    /**
     * Set information bout the source of the Certificate (TRUSTED_LIST, TRUST_STORE, ...)
     * 
     * @param certificateSource
     */
    public void setCertificateSource(CertificateSourceType certificateSource) {
        this.certificateSource = certificateSource;
    }

    /**
     * Get information about the context from which the certificate is fetched
     * 
     * @return
     */
    public Serializable getContext() {
        return context;
    }

    /**
     * Set information about the context from which the certificate if fetched
     * 
     * @param context
     */
    public void setContext(Serializable context) {
        this.context = context;
    }

    @Override
    public String toString() {
        return "Certificate[for=" + certificate.getSubjectDN().getName() + ",source=" + certificateSource
                + ",issuedBy=" + certificate.getIssuerX500Principal() + ",serial=" + certificate.getSerialNumber()
                + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((certificate == null) ? 0 : certificate.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        CertificateAndContext other = (CertificateAndContext) obj;
        if (certificate == null) {
            if (other.certificate != null) {
                return false;
            }
        } else if (!certificate.equals(other.certificate)) {
            return false;
        }
        return true;
    }

}
