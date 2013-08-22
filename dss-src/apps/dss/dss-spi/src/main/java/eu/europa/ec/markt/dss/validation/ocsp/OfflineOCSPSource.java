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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.SingleResp;

/**
 * Abstract class that helps to implements OCSPSource with a already loaded list of BasicOCSPResp
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public abstract class OfflineOCSPSource implements OCSPSource {

    private static final Logger LOG = Logger.getLogger(OfflineOCSPSource.class.getName());

    @Override
    final public BasicOCSPResp getOCSPResponse(X509Certificate certificate, X509Certificate issuerCertificate)
            throws IOException {
        LOG.fine("find OCSP response");

        try {
            for (BasicOCSPResp basicOCSPResp : getOCSPResponsesFromSignature()) {

                CertificateID certId = new CertificateID(CertificateID.HASH_SHA1, issuerCertificate,
                        certificate.getSerialNumber());
                for (SingleResp singleResp : basicOCSPResp.getResponses()) {
                    if (singleResp.getCertID().equals(certId)) {
                        LOG.fine("OCSP response found");
                        return basicOCSPResp;
                    }
                }
            }

            ocspNotFound(certificate, issuerCertificate);
            return null;

        } catch (OCSPException e) {
            LOG.severe("OCSPException: " + e.getMessage());
            return null;
        }

    }

    /**
     * Callback used when the OCSP is not found.
     * 
     * @param certificate
     * @param issuerCertificate
     */
    public void ocspNotFound(X509Certificate certificate, X509Certificate issuerCertificate) throws IOException {

    }

    /**
     * Retrieve the list of BasicOCSPResp contained in the Signature.
     * 
     * @return
     */
    public abstract List<BasicOCSPResp> getOCSPResponsesFromSignature();

}
