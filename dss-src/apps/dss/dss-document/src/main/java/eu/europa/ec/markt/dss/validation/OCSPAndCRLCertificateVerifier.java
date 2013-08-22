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

import eu.europa.ec.markt.dss.validation.crl.CRLCertificateVerifier;
import eu.europa.ec.markt.dss.validation.crl.CRLSource;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPCertificateVerifier;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPSource;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Logger;

/**
 * 
 * Fetch revocation data from a certificate by querying a OCSP server first and then an CRL server if no OCSP response
 * could be retrieved.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class OCSPAndCRLCertificateVerifier implements CertificateStatusVerifier {

    private static final Logger LOG = Logger.getLogger(OCSPAndCRLCertificateVerifier.class.getName());

    private OCSPSource ocspSource;

    private CRLSource crlSource;

    /**
     * 
     * The default constructor for OCSPAndCRLCertificateVerifier.
     */
    public OCSPAndCRLCertificateVerifier() {
    }

    /**
     * Build a OCSPAndCRLCertificateVerifier that will use the provided CRLSource and OCSPSource
     */
    public OCSPAndCRLCertificateVerifier(CRLSource crlSource, OCSPSource ocspSource) {
        this.crlSource = crlSource;
        this.ocspSource = ocspSource;
    }

    /**
     * Get the OCSP Source from this verifier
     * 
     * @return
     */
    public OCSPSource getOcspSource() {
        return ocspSource;
    }

    /**
     * Set the OCSP source for this verifier
     * 
     * @param ocspSource
     */
    public void setOcspSource(OCSPSource ocspSource) {
        this.ocspSource = ocspSource;
    }

    /**
     * Get the CRL source from this verifier
     * 
     * @return
     */
    public CRLSource getCrlSource() {
        return crlSource;
    }

    /**
     * Set the CRL source for this verifier
     * 
     * @param crlSource
     */
    public void setCrlSource(CRLSource crlSource) {
        this.crlSource = crlSource;
    }

    @Override
    public CertificateStatus check(X509Certificate cert, X509Certificate potentialIssuer, Date validationDate) {

        CertificateStatusVerifier ocspVerifier = new OCSPCertificateVerifier(getOcspSource());
        LOG.info("OCSP request for " + cert.getSubjectDN());
        CertificateStatus result = ocspVerifier.check(cert, potentialIssuer, validationDate);
        if (result != null && result.getValidity() != CertificateValidity.UNKNOWN) {

            /*
             * Valid or not, an OCSP response has been retrieved. One should look in the ValidationReport to see the
             * result
             */
            LOG.fine("OCSP validation done, don't need for CRL");
            return result;

        } else {

            LOG.info("No OCSP check performed, looking for a CRL for " + cert.getSubjectDN());

            CRLCertificateVerifier crlVerifier = new CRLCertificateVerifier(getCrlSource());
            result = crlVerifier.check(cert, potentialIssuer, validationDate);
            if (result != null && result.getValidity() != CertificateValidity.UNKNOWN) {
                LOG.info("CRL check has been performed. Valid or not, the verification is done");
                return result;
            } else {
                LOG.info("We had no response from OCSP nor CRL");
                return null;
            }
        }
    }

}
