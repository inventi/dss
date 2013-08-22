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

package eu.europa.ec.markt.dss.validation.ocsp;

import eu.europa.ec.markt.dss.validation.CertificateStatus;
import eu.europa.ec.markt.dss.validation.CertificateStatusVerifier;
import eu.europa.ec.markt.dss.validation.CertificateValidity;
import eu.europa.ec.markt.dss.validation.ValidatorSourceType;

import java.io.IOException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;

/**
 * Check the status of the certificate using an OCSPSource
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class OCSPCertificateVerifier implements CertificateStatusVerifier {

    private static final Logger LOG = Logger.getLogger(OCSPCertificateVerifier.class.getName());

    private final OCSPSource ocspSource;

    /**
     * Create a CertificateVerifier that will use the OCSP Source for checking revocation data. The default constructor
     * for OCSPCertificateVerifier.
     * 
     * @param ocspSource
     */
    public OCSPCertificateVerifier(OCSPSource ocspSource) {
        Security.addProvider(new BouncyCastleProvider());
        this.ocspSource = ocspSource;
    }

    @Override
    public CertificateStatus check(X509Certificate childCertificate, X509Certificate certificate, Date validationDate) {

        CertificateStatus status = new CertificateStatus();
        status.setCertificate(childCertificate);
        status.setValidationDate(validationDate);
        status.setIssuerCertificate(certificate);

        if (ocspSource == null) {
            LOG.warning("OCSPSource null");
            return null;
        }

        try {
            BasicOCSPResp ocspResp = ocspSource.getOCSPResponse(childCertificate, certificate);
            if (null == ocspResp) {
                LOG.info("OCSP response not found");
                return null;
            }

            BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp;

            CertificateID certificateId = new CertificateID(CertificateID.HASH_SHA1, certificate,
                    childCertificate.getSerialNumber());
            SingleResp[] singleResps = basicOCSPResp.getResponses();
            for (SingleResp singleResp : singleResps) {

                CertificateID responseCertificateId = singleResp.getCertID();

                if (false == certificateId.equals(responseCertificateId)) {
                    continue;
                }

                Date thisUpdate = singleResp.getThisUpdate();
                LOG.fine("OCSP thisUpdate: " + thisUpdate);
                LOG.fine("OCSP nextUpdate: " + singleResp.getNextUpdate());

                status.setStatusSourceType(ValidatorSourceType.OCSP);
                status.setStatusSource(ocspResp);
                status.setRevocationObjectIssuingTime(ocspResp.getProducedAt());

                if (null == singleResp.getCertStatus()) {
                    LOG.info("OCSP OK for: " + childCertificate.getSubjectX500Principal());
                    status.setValidity(CertificateValidity.VALID);
                } else {
                    LOG.info("OCSP certificate status: " + singleResp.getCertStatus().getClass().getName());
                    if (singleResp.getCertStatus() instanceof RevokedStatus) {
                        LOG.info("OCSP status revoked");
                        if (validationDate.before(((RevokedStatus) singleResp.getCertStatus()).getRevocationTime())) {
                            LOG.info("OCSP revocation time after the validation date, the certificate was valid at "
                                    + validationDate);
                            status.setValidity(CertificateValidity.VALID);
                        } else {
                            status.setRevocationDate(((RevokedStatus) singleResp.getCertStatus()).getRevocationTime());
                            status.setValidity(CertificateValidity.REVOKED);
                        }
                    } else if (singleResp.getCertStatus() instanceof UnknownStatus) {
                        LOG.info("OCSP status unknown");
                        status.setValidity(CertificateValidity.UNKNOWN);
                    }
                }

                return status;
            }

            LOG.fine("no matching OCSP response entry");
            return null;
        } catch (IOException ex) {
            LOG.log(Level.SEVERE, "OCSP exception: " + ex.getMessage(), ex);
            return null;
        } catch (OCSPException ex) {
            LOG.severe("OCSP exception: " + ex.getMessage());
            throw new RuntimeException(ex);
        }

    }

}
