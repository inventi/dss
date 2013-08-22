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

import eu.europa.ec.markt.dss.CannotFetchDataException;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/**
 *
 * Use the AIA attribute of a certificate to retrieve the issuer
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class AIACertificateSource implements CertificateSource {

    private static final Logger LOG = Logger.getLogger(AIACertificateSource.class.getName());

    private X509Certificate certificate;

    private HTTPDataLoader httpDataLoader;

    /**
     * The default constructor for AIACertificateSource.
     */
    public AIACertificateSource(X509Certificate certificate, HTTPDataLoader httpDataLoader) {
        this.certificate = certificate;
        this.httpDataLoader = httpDataLoader;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * eu.europa.ec.markt.dss.validation.certificate.CertificateSource#getCertificateBySubjectName(javax.security.auth
     * .x500.X500Principal)
     */
    @Override
    public List<CertificateAndContext> getCertificateBySubjectName(X500Principal subjectName) {
        List<CertificateAndContext> list = new ArrayList<CertificateAndContext>();

        try {
            String url = getAccessLocation(certificate, X509ObjectIdentifiers.id_ad_caIssuers);

            if (url != null) {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) factory.generateCertificate(httpDataLoader.get(url));
                
                if (cert.getSubjectX500Principal().equals(subjectName)) {
                    list.add(new CertificateAndContext());
                } 

            }
        } catch (CannotFetchDataException e) {
            return Collections.emptyList();
        } catch (CertificateException e) {
            return Collections.emptyList();
        }

        return list;
    }

    @SuppressWarnings("deprecation")
    private String getAccessLocation(X509Certificate certificate, DERObjectIdentifier accessMethod) {
        try {

            byte[] authInfoAccessExtensionValue = certificate.getExtensionValue(X509Extensions.AuthorityInfoAccess
                    .getId());

            /* If the extension is not there, then return null */
            if (null == authInfoAccessExtensionValue) {
                return null;
            }

            /* Parse the extension */
            AuthorityInformationAccess authorityInformationAccess;
            DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(
                    authInfoAccessExtensionValue)).readObject());
            authorityInformationAccess = new AuthorityInformationAccess((ASN1Sequence) new ASN1InputStream(
                    oct.getOctets()).readObject());

            AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
            for (AccessDescription accessDescription : accessDescriptions) {
                LOG.fine("access method: " + accessDescription.getAccessMethod());
                boolean correctAccessMethod = accessDescription.getAccessMethod().equals(accessMethod);
                if (!correctAccessMethod) {
                    continue;
                }
                GeneralName gn = accessDescription.getAccessLocation();
                if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {
                    LOG.fine("not a uniform resource identifier");
                    continue;
                }
                DERIA5String str = (DERIA5String) ((DERTaggedObject) gn.getDERObject()).getObject();
                String accessLocation = str.getString();
                LOG.fine("access location: " + accessLocation);
                return accessLocation;
            }
            return null;

        } catch (IOException e) {
            throw new RuntimeException("IO error: " + e.getMessage(), e);
        }
    }

}
