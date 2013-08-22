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

package eu.europa.ec.markt.dss.validation.x509;

import eu.europa.ec.markt.dss.validation.CertificateStatus;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceFactory;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

/**
 * SignedToken containing a X509Certificate 
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class CertificateToken implements SignedToken {

    private CertificateSourceFactory sourceFactory;

    private CertificateAndContext cert;

    private CertificateStatus status;

    /**
     * Create a CertificateToken
     * 
     * @param cert
     */
    public CertificateToken(CertificateAndContext cert) {
        this(cert, null);
    }

    /**
     * Create a CertificateToken
     * 
     * @param cert
     * @param sourceFactory
     */
    public CertificateToken(CertificateAndContext cert, CertificateSourceFactory sourceFactory) {
        this.cert = cert;
        this.sourceFactory = sourceFactory;
    }

    @Override
    public X500Principal getSignerSubjectName() {
        return cert.getCertificate().getIssuerX500Principal();
    }

    /**
     * @return the cert
     */
    public CertificateAndContext getCertificateAndContext() {
        return cert;
    }

    /**
     * @return the cert
     */
    public X509Certificate getCertificate() {
        return cert.getCertificate();
    }

    @Override
    public boolean isSignedBy(X509Certificate potentialIssuer) {
        try {
            getCertificate().verify(potentialIssuer.getPublicKey());
            return true;
        } catch (InvalidKeyException e) {
            return false;
        } catch (CertificateException e) {
            return false;
        } catch (NoSuchAlgorithmException e) {
            return false;
        } catch (NoSuchProviderException e) {
            /*
             * This should never happens. The provider BouncyCastle is supposed to be installed. No special treatment
             * for this exception
             */
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            return false;
        }
    }

    /**
     * @param status the status to set
     */
    public void setStatus(CertificateStatus status) {
        this.status = status;
    }

    /**
     * @return the status
     */
    public CertificateStatus getStatus() {
        return status;
    }

    /**
     * An X509Certificate may contain information about his issuer in the AIA attribute.
     */
    @Override
    public CertificateSource getWrappedCertificateSource() {
        if (sourceFactory != null) {
            CertificateSource source = sourceFactory.createAIACertificateSource(getCertificate());
            return source;
        } else {
            return null;
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        try {
            result = prime * result + ((cert == null) ? 0 : Arrays.hashCode(getCertificate().getEncoded()));
        } catch (CertificateException ex) {
            return prime;
        }
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
        CertificateToken other = (CertificateToken) obj;
        if (cert == null) {
            if (other.cert != null) {
                return false;
            }
        } else if (!cert.equals(other.cert)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "Certificate[subjectName=\"" + getCertificate().getSubjectDN() + "\",issuedBy=\""
                + getCertificate().getIssuerX500Principal() + "\"]";
    }

}
