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

package eu.europa.ec.markt.dss.applet.service;

import eu.europa.ec.markt.dss.EncodingException;
import eu.europa.ec.markt.dss.EncodingException.MSG;
import eu.europa.ec.markt.dss.applet.shared.PotentialIssuerRequestMessage;
import eu.europa.ec.markt.dss.applet.shared.PotentialIssuerResponseMessage;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;

import java.io.IOException;
import java.io.Serializable;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

/**
 * Return all the matching X509Certificate according to the X500Principal
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class PotentialIssuersRequestHandler extends
        AbstractServiceHandler<PotentialIssuerRequestMessage, PotentialIssuerResponseMessage> {

    private static final Logger LOG = Logger.getLogger(PotentialIssuersRequestHandler.class.getName());

    private CertificateSource certificateSource;

    /**
     * @param certificateSource the certificateSource to set
     */
    public void setCertificateSource(CertificateSource certificateSource) {
        this.certificateSource = certificateSource;
    }

    @Override
    protected PotentialIssuerResponseMessage handleRequest(PotentialIssuerRequestMessage message) throws IOException {

        try {
            X500Principal principal = new X500Principal(message.getIssuerPrincipal());

            PotentialIssuerResponseMessage response = new PotentialIssuerResponseMessage();

            List<CertificateAndContext> certs = certificateSource.getCertificateBySubjectName(principal);
            if (certs != null) {
                byte[][] potentialIssuers = new byte[certs.size()][];
                String[] sources = new String[certs.size()];
                Serializable[] context = new Serializable[certs.size()];
                for (int i = 0; i < certs.size(); i++) {
                    potentialIssuers[i] = certs.get(i).getCertificate().getEncoded();
                    sources[i] = certs.get(i).getCertificateSource().toString();
                    context[i] = certs.get(i).getContext();
                }
                response.setPotentialIssuers(potentialIssuers);
                response.setCertificateContext(sources);
                response.setCertificateContextInfo(context);
            }

            return response;
        } catch (CertificateException ex) {
            LOG.log(Level.SEVERE, null, ex);
            throw new EncodingException(MSG.CERTIFICATE_CANNOT_BE_READ);
        }
    }

}
