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

package eu.europa.ec.markt.dss.validation.crl;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Logger;

/**
 *
 *  
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public abstract class OfflineCRLSource implements CRLSource {

    private static final Logger LOG = Logger.getLogger(OfflineCRLSource.class.getName());

    @Override
    final public X509CRL findCrl(X509Certificate certificate, X509Certificate issuerCertificate) {

        for (X509CRL crl : getCRLsFromSignature()) {
            if (crl.getIssuerX500Principal().equals(issuerCertificate.getSubjectX500Principal())) {
                LOG.fine("CRL found for issuer " + issuerCertificate.getSubjectX500Principal().toString());
                return crl;
            }
        }

        LOG.fine("CRL not found for issuer " + issuerCertificate.getSubjectX500Principal().toString());
        return null;
    }

    /**
     * Retrieve the list of CRL contained in the Signature
     * 
     * @return
     */
    public abstract List<X509CRL> getCRLsFromSignature();

}
