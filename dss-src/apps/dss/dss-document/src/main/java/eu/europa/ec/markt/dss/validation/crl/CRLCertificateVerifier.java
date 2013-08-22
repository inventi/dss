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

import eu.europa.ec.markt.dss.validation.CertificateStatus;
import eu.europa.ec.markt.dss.validation.CertificateStatusVerifier;
import eu.europa.ec.markt.dss.validation.CertificateValidity;
import eu.europa.ec.markt.dss.validation.ValidatorSourceType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.X509Extensions;

/**
 * Verifier based on CRL
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class CRLCertificateVerifier implements CertificateStatusVerifier {

    private static final Logger LOG = Logger.getLogger(CRLCertificateVerifier.class.getName());

    private final CRLSource crlSource;

    /**
     * Main constructor.
     * 
     * @param crlSource the CRL repository used by this CRL trust linker.
     */
    public CRLCertificateVerifier(CRLSource crlSource) {
        this.crlSource = crlSource;
    }

    @Override
    public CertificateStatus check(X509Certificate childCertificate, X509Certificate certificate, Date validationDate) {

        try {

            CertificateStatus report = new CertificateStatus();
            report.setCertificate(childCertificate);
            report.setValidationDate(validationDate);
            report.setIssuerCertificate(certificate);

            if (crlSource == null) {
                LOG.warning("CRLSource null");
                return null;
            }

            X509CRL x509crl = crlSource.findCrl(childCertificate, certificate);
            if (x509crl == null) {
                LOG.info("No CRL found for certificate " + childCertificate.getSubjectDN());
                return null;
            }

            if (!isCRLValid(x509crl, certificate, validationDate)) {
                LOG.warning("The CRL is not valid !");
                return null;
            }
            report.setStatusSource(x509crl);

            /* by default, we claim that the certifate if invalid */
            report.setValidity(CertificateValidity.UNKNOWN);
            report.setCertificate(childCertificate);
            report.setStatusSourceType(ValidatorSourceType.CRL);
            report.setValidationDate(validationDate);
            X509CRLEntry crlEntry = x509crl.getRevokedCertificate(childCertificate.getSerialNumber());
            if (null == crlEntry) {
                LOG.fine("CRL OK for: " + childCertificate.getSubjectX500Principal());
                /*
                 * If there is no entry in the CRL, the certificate is more likely to be valid
                 */
                report.setValidity(CertificateValidity.VALID);
            } else if (crlEntry.getRevocationDate().after(validationDate)) {
                LOG.fine("CRL OK for: " + childCertificate.getSubjectX500Principal() + " at " + validationDate);
                /*
                 * Even if there is an entry, the certificate can be valid at the time of the validation
                 */
                report.setValidity(CertificateValidity.VALID);
                report.setRevocationObjectIssuingTime(x509crl.getThisUpdate());
            } else {
                LOG.fine("CRL reports certificate: " + childCertificate.getSubjectX500Principal()
                        + " as revoked since " + crlEntry.getRevocationDate());
                report.setValidity(CertificateValidity.REVOKED);
                report.setRevocationObjectIssuingTime(x509crl.getThisUpdate());
                report.setRevocationDate(crlEntry.getRevocationDate());
            }

            return report;

        } catch (IOException e) {
            LOG.log(Level.SEVERE, "IOException when accessing CRL for " + childCertificate.getSubjectDN(), e);
            return null;
        }

    }

    private boolean isCRLValid(X509CRL x509crl, X509Certificate issuerCertificate, Date validationDate) {

        if (!isCRLOK(x509crl, issuerCertificate, validationDate)) {

            return false;

        } else {

            LOG.fine("CRL number: " + getCrlNumber(x509crl));

            return true;
        }

    }

    private boolean isCRLOK(X509CRL x509crl, X509Certificate issuerCertificate, Date validationDate) {

        if (issuerCertificate == null) {
            throw new NullPointerException("Must provide a issuer certificate to validate the signature");
        }

        /* The CRL must be signed by the issuer */
        if (!x509crl.getIssuerX500Principal().equals(issuerCertificate.getSubjectX500Principal())) {
            LOG.warning("The CRL must be signed by the issuer (" + issuerCertificate.getSubjectDN()
                    + " ) but instead is signed by " + x509crl.getIssuerX500Principal());
            return false;
        }

        try {
            x509crl.verify(issuerCertificate.getPublicKey());
        } catch (Exception e) {
            LOG.warning("The signature verification for CRL cannot be performed : " + e.getMessage());
            return false;
        }

        /* The CRL must be valid at the time of validation */
        Date thisUpdate = x509crl.getThisUpdate();
        LOG.fine("validation date: " + validationDate);
        LOG.fine("CRL this update: " + thisUpdate);
        /* CRL issued after the reference time: is it really important?! */
//        if (thisUpdate.after(validationDate)) {
//            LOG.warning("CRL too young");
//            return false;
//        }
        LOG.fine("CRL next update: " + x509crl.getNextUpdate());
        if (x509crl.getNextUpdate() != null && validationDate.after(x509crl.getNextUpdate())) {
            LOG.info("CRL too old");
            return false;
        }

        // assert cRLSign KeyUsage bit
        if (null == issuerCertificate.getKeyUsage()) {
            LOG.warning("No KeyUsage extension for CRL issuing certificate");
            return false;
        }

        if (false == issuerCertificate.getKeyUsage()[6]) {
            LOG.warning("cRLSign bit not set for CRL issuing certificate");
            return false;
        }

        return true;
    }

    private BigInteger getCrlNumber(X509CRL crl) {
        byte[] crlNumberExtensionValue = crl.getExtensionValue(X509Extensions.CRLNumber.getId());
        if (null == crlNumberExtensionValue) {
            return null;
        }
        try {
            DEROctetString octetString = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(
                    crlNumberExtensionValue)).readObject());
            byte[] octets = octetString.getOctets();
            DERInteger integer = (DERInteger) new ASN1InputStream(octets).readObject();
            BigInteger crlNumber = integer.getPositiveValue();
            return crlNumber;
        } catch (IOException e) {
            throw new RuntimeException("IO error: " + e.getMessage(), e);
        }
    }

}
