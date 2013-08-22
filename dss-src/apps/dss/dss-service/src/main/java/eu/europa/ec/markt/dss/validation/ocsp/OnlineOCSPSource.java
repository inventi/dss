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

import eu.europa.ec.markt.dss.CannotFetchDataException;
import eu.europa.ec.markt.dss.validation.https.HTTPDataLoader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;

/**
 * Online OCSP repository. This implementation will contact the OCSP Responder to retrieve the OCSP response.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class OnlineOCSPSource implements OCSPSource {

    private static final Logger LOG = Logger.getLogger(OnlineOCSPSource.class.getName());

    private HTTPDataLoader httpDataLoader;

    /**
     * Create an OCSP source The default constructor for OnlineOCSPSource.
     */
    public OnlineOCSPSource() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Set the HTTPDataLoader to use for querying the OCSP server.
     * 
     * @param httpDataLoader
     */
    public void setHttpDataLoader(HTTPDataLoader httpDataLoader) {
        this.httpDataLoader = httpDataLoader;
    }

    @Override
    public BasicOCSPResp getOCSPResponse(X509Certificate certificate, X509Certificate issuerCertificate)
            throws IOException {
        try {
            String ocspUri = getAccessLocation(certificate, X509ObjectIdentifiers.ocspAccessMethod);
            LOG.fine("OCSP URI: " + ocspUri);
            if (ocspUri == null) {
                return null;
            }

            OCSPReqGenerator ocspReqGenerator = new OCSPReqGenerator();
            CertificateID certId = new CertificateID(CertificateID.HASH_SHA1, issuerCertificate,
                    certificate.getSerialNumber());
            ocspReqGenerator.addRequest(certId);
            OCSPReq ocspReq = ocspReqGenerator.generate();
            byte[] ocspReqData = ocspReq.getEncoded();

            OCSPResp ocspResp = new OCSPResp(httpDataLoader.post(ocspUri, new ByteArrayInputStream(ocspReqData)));
            try {
				return (BasicOCSPResp) ocspResp.getResponseObject();
			} catch (NullPointerException e) {
				// Encountered a case when the OCSPResp is initialized with a null OCSP response...
				// (and there are no nullity checks in the OCSPResp implementation)
				return null;
			}
        } catch (CannotFetchDataException e) {
            return null;
        } catch (OCSPException e) {
            LOG.severe("OCSP error: " + e.getMessage());
            return null;
        }
    }

    @SuppressWarnings("deprecation")
    private String getAccessLocation(X509Certificate certificate, DERObjectIdentifier accessMethod)
            throws IOException {
        byte[] authInfoAccessExtensionValue = certificate.getExtensionValue(X509Extensions.AuthorityInfoAccess
                .getId());
        if (null == authInfoAccessExtensionValue) {
            return null;
        }
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

    }

}
