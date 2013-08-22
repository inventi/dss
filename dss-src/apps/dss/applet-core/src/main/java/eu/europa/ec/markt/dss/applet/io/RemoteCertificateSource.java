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

package eu.europa.ec.markt.dss.applet.io;

import eu.europa.ec.markt.dss.applet.shared.PotentialIssuerRequestMessage;
import eu.europa.ec.markt.dss.applet.shared.PotentialIssuerResponseMessage;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

/**
 * CertificateSource that use the server backend for the operation execution.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class RemoteCertificateSource extends
        AbstractRemoteService<PotentialIssuerRequestMessage, PotentialIssuerResponseMessage> implements
        CertificateSource {

    @Override
    public List<CertificateAndContext> getCertificateBySubjectName(X500Principal subjectName) throws IOException {

        try {
            PotentialIssuerRequestMessage request = new PotentialIssuerRequestMessage();
            request.setIssuerPrincipal(subjectName.getEncoded());

            PotentialIssuerResponseMessage response = sendAndReceive(request);

            CertificateFactory factory = CertificateFactory.getInstance("X509");
            List<CertificateAndContext> certs = new ArrayList<CertificateAndContext>();
            if (response.getPotentialIssuers() != null) {
                for (int i = 0; i < response.getPotentialIssuers().length; i++) {
                    CertificateAndContext ctx = new CertificateAndContext();
                    ctx.setCertificate((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(
                            response.getPotentialIssuers()[i])));
                    if (response.getCertificateContext() != null && response.getCertificateContext()[i] != null) {
                        ctx.setCertificateSource(CertificateSourceType.valueOf(response.getCertificateContext()[i]));
                    }
                    if (response.getCertificateContextInfo() != null
                            && response.getCertificateContextInfo()[i] != null) {
                        ctx.setContext(response.getCertificateContextInfo()[i]);
                    }
                    certs.add(ctx);
                }
            }
            return certs;
        } catch (CertificateException ex) {
            throw new IOException(ex);
        }
    }

}
