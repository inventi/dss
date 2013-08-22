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

package eu.europa.ec.markt.dss.validation.cades;

import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.CRLRef;
import eu.europa.ec.markt.dss.validation.CertificateRef;
import eu.europa.ec.markt.dss.validation.OCSPRef;
import eu.europa.ec.markt.dss.validation.PolicyValue;
import eu.europa.ec.markt.dss.validation.SignatureFormat;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken;

import java.io.IOException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.esf.SignerAttribute;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * 
 * CAdES Signature class helper
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class CAdESSignature implements AdvancedSignature {

    public static final ASN1ObjectIdentifier id_aa_ets_archiveTimestampV2 = PKCSObjectIdentifiers.id_aa.branch("48");

    private static Logger LOG = Logger.getLogger(CAdESSignature.class.getName());

    private CMSSignedData cmsSignedData;
    private SignerInformation signerInformation;

    /**
     * 
     * The default constructor for CAdESSignature.
     * 
     * @param data
     * @throws CMSException
     */
    public CAdESSignature(byte[] data) throws CMSException {
        this(new CMSSignedData(data));
    }

    /**
     * 
     * The default constructor for CAdESSignature.
     * 
     * @param data
     * @throws CMSException
     */
    public CAdESSignature(CMSSignedData cms) {
        this(cms, (SignerInformation) cms.getSignerInfos().getSigners().iterator().next());
    }

    /**
     * 
     * The default constructor for CAdESSignature.
     * 
     * @param data
     * @throws CMSException
     */
    public CAdESSignature(CMSSignedData cms, SignerInformation signerInformation) {
        this.cmsSignedData = cms;
        this.signerInformation = signerInformation;
    }

    /**
     * 
     * The default constructor for CAdESSignature.
     * 
     * @param data
     * @throws CMSException
     */
    public CAdESSignature(CMSSignedData cms, SignerId id) {
        this(cms, cms.getSignerInfos().get(id));
    }

    @Override
    public SignatureFormat getSignatureFormat() {
        return SignatureFormat.CAdES;
    }

    @Override
    public CAdESCertificateSource getCertificateSource() {
        return new CAdESCertificateSource(cmsSignedData, signerInformation.getSID(), false);
    }

    @Override
    public CertificateSource getExtendedCertificateSource() {
        return new CAdESCertificateSource(cmsSignedData, signerInformation.getSID(), true);
    }

    @Override
    public CAdESCRLSource getCRLSource() {
        return new CAdESCRLSource(cmsSignedData, signerInformation.getSID());
    }

    @Override
    public CAdESOCSPSource getOCSPSource() {
        return new CAdESOCSPSource(cmsSignedData, signerInformation.getSID());
    }

    @Override
    public X509Certificate getSigningCertificate() {

        LOG.info("SignerInformation " + signerInformation.getSID());
        Collection<X509Certificate> certs = getCertificates();
        for (X509Certificate cert : certs) {
            LOG.info("Test match for certificate " + cert.getSubjectDN().getName());
            if (signerInformation.getSID().match(cert)) {
                return cert;
            }
        }

        return null;
    }

    @Override
    public List<X509Certificate> getCertificates() {
        return getCertificateSource().getCertificates();
    }

    @Override
    public PolicyValue getPolicyId() {
        if (signerInformation.getSignedAttributes() == null) {
            return null;
        }
        Attribute sigPolicytAttr = signerInformation.getSignedAttributes().get(
                PKCSObjectIdentifiers.id_aa_ets_sigPolicyId);
        if (sigPolicytAttr == null) {
            return null;
        }

        if(sigPolicytAttr.getAttrValues().getObjectAt(0) instanceof DERNull) {
            return new PolicyValue();
        }
        
        SignaturePolicyId sigPolicy = null;
        sigPolicy = SignaturePolicyId.getInstance(sigPolicytAttr.getAttrValues().getObjectAt(0));

        if (sigPolicy == null) {
            return new PolicyValue();
        }

        return new PolicyValue(sigPolicy.getSigPolicyId().getId());
    }

    @Override
    public Date getSigningTime() {
        if (signerInformation.getSignedAttributes() != null
                && signerInformation.getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_signingTime) != null) {
            ASN1Set set = signerInformation.getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_signingTime)
                    .getAttrValues();
            try {
                Object o = set.getObjectAt(0);
                if (o instanceof ASN1UTCTime) {
                    return ((ASN1UTCTime) o).getDate();
                }
                if (o instanceof Time) {
                    return ((Time) o).getDate();
                }
                LOG.log(Level.SEVERE, "Error when reading signing time. Unrecognized " + o.getClass());
            } catch (Exception ex) {
                LOG.log(Level.SEVERE, "Error when reading signing time ", ex);
                return null;
            }
        }
        return null;
    }

    /**
     * @return the cmsSignedData
     */
    public CMSSignedData getCmsSignedData() {
        return cmsSignedData;
    }

    @Override
    public String getLocation() {
        return null;
    }

    @Override
    public String[] getClaimedSignerRoles() {

        if (signerInformation.getSignedAttributes() == null) {
            return null;
        }

        Attribute signerAttrAttr = signerInformation.getSignedAttributes().get(
                PKCSObjectIdentifiers.id_aa_ets_signerAttr);
        if (signerAttrAttr == null) {
            return null;
        }

        SignerAttribute signerAttr = null;
        signerAttr = SignerAttribute.getInstance(signerAttrAttr.getAttrValues().getObjectAt(0));

        if (signerAttr == null) {
            return null;
        }

        String[] ret = new String[signerAttr.getClaimedAttributes().size()];
        for (int i = 0; i < signerAttr.getClaimedAttributes().size(); i++) {
            if (signerAttr.getClaimedAttributes().getObjectAt(i) instanceof DEROctetString) {
                ret[i] = new String(((DEROctetString) signerAttr.getClaimedAttributes().getObjectAt(i)).getOctets());

            } else {
                ret[i] = signerAttr.getClaimedAttributes().getObjectAt(i).toString();
            }
        }

        return ret;
    }

    private List<TimestampToken> getTimestampList(ASN1ObjectIdentifier attrType,
            TimestampToken.TimestampType timestampType) {
        if (signerInformation.getUnsignedAttributes() != null) {
            Attribute timeStampAttr = signerInformation.getUnsignedAttributes().get(attrType);
            if (timeStampAttr == null) {
                return null;
            }

            List<TimestampToken> tstokens = new ArrayList<TimestampToken>();
            for (ASN1Encodable value : timeStampAttr.getAttrValues().toArray()) {
                try {
                    TimeStampToken token = new TimeStampToken(new CMSSignedData(value.getDEREncoded()));
                    tstokens.add(new TimestampToken(token, timestampType));
                } catch (Exception e) {
                    throw new RuntimeException("Parsing error", e);
                }
            }

            return tstokens;
        } else {
            return null;
        }
    }

    protected List<TimestampToken> getContentTimestamps() {
        return getTimestampList(PKCSObjectIdentifiers.id_aa_ets_contentTimestamp,
                TimestampToken.TimestampType.CONTENT_TIMESTAMP);
    }

    @Override
    public List<TimestampToken> getSignatureTimestamps() throws RuntimeException {
        return getTimestampList(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                TimestampToken.TimestampType.SIGNATURE_TIMESTAMP);
    }

    @Override
    public List<TimestampToken> getTimestampsX1() {
        return getTimestampList(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp,
                TimestampToken.TimestampType.VALIDATION_DATA_TIMESTAMP);
    }

    @Override
    public List<TimestampToken> getTimestampsX2() {
        return getTimestampList(PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp,
                TimestampToken.TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
    }

    @Override
    public List<TimestampToken> getArchiveTimestamps() {
        return getTimestampList(id_aa_ets_archiveTimestampV2,
                TimestampToken.TimestampType.ARCHIVE_TIMESTAMP);
    }

    @Override
    public String getSignatureAlgorithm() {
        return signerInformation.getEncryptionAlgOID();
    }

    @Override
    public boolean checkIntegrity(Document detachedDocument) {
        JcaSimpleSignerInfoVerifierBuilder verifier = new JcaSimpleSignerInfoVerifierBuilder();
        try {
            boolean ret = false;

            SignerInformation si = null;
            if (detachedDocument != null) {
                // Recreate a SignerInformation with the content using a CMSSignedDataParser
                CMSSignedDataParser sp = new CMSSignedDataParser(new CMSTypedStream(detachedDocument.openStream()),
                        cmsSignedData.getEncoded());
                sp.getSignedContent().drain();
                si = sp.getSignerInfos().get(signerInformation.getSID());
            } else {
                si = this.signerInformation;
            }

            ret = si.verify(verifier.build(getSigningCertificate()));

            return ret;

        } catch (OperatorCreationException e) {
            return false;
        } catch (CMSException e) {
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    @Override
    public String getContentType() {
        return signerInformation.getContentType().toString();
    }

    /**
     * @return the signerInformation
     */
    public SignerInformation getSignerInformation() {
        return signerInformation;
    }

    @Override
    public List<AdvancedSignature> getCounterSignatures() {

        List<AdvancedSignature> counterSigs = new ArrayList<AdvancedSignature>();
        for (Object o : this.signerInformation.getCounterSignatures().getSigners()) {
            SignerInformation i = (SignerInformation) o;

            CAdESSignature info = new CAdESSignature(this.cmsSignedData, i.getSID());
            counterSigs.add(info);
        }

        return counterSigs;
    }

    @Override
    public List<CertificateRef> getCertificateRefs() {
        List<CertificateRef> list = new ArrayList<CertificateRef>();

        if (signerInformation.getUnsignedAttributes() != null) {
            Attribute completeCertRefsAttr = signerInformation.getUnsignedAttributes().get(
                    PKCSObjectIdentifiers.id_aa_ets_certificateRefs);
            if (completeCertRefsAttr != null && completeCertRefsAttr.getAttrValues().size() > 0) {
                DERSequence completeCertificateRefs = (DERSequence) completeCertRefsAttr.getAttrValues()
                        .getObjectAt(0);
                for (int i1 = 0; i1 < completeCertificateRefs.size(); i1++) {
                    OtherCertID otherCertId = OtherCertID.getInstance(completeCertificateRefs.getObjectAt(i1));
                    CertificateRef certId = new CertificateRef();
                    certId.setDigestAlgorithm(otherCertId.getAlgorithmHash().getAlgorithm().getId());
                    certId.setDigestValue(otherCertId.getCertHash());
                    if (otherCertId.getIssuerSerial() != null) {
                        if (otherCertId.getIssuerSerial().getIssuer() != null) {
                            certId.setIssuerName(otherCertId.getIssuerSerial().getIssuer().toString());
                        }
                        if (otherCertId.getIssuerSerial().getSerial() != null) {
                            certId.setIssuerSerial(otherCertId.getIssuerSerial().getSerial().toString());
                        }
                    }
                    list.add(certId);
                }
            }
        }

        return list;
    }

    @Override
    public List<CRLRef> getCRLRefs() {
        List<CRLRef> list = new ArrayList<CRLRef>();

        if (signerInformation.getUnsignedAttributes() != null) {
            Attribute completeRevocationRefsAttr = signerInformation.getUnsignedAttributes().get(
                    PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
            if (completeRevocationRefsAttr != null && completeRevocationRefsAttr.getAttrValues().size() > 0) {
                DERSequence completeCertificateRefs = (DERSequence) completeRevocationRefsAttr.getAttrValues()
                        .getObjectAt(0);
                for (int i1 = 0; i1 < completeCertificateRefs.size(); i1++) {
                    CrlOcspRef otherCertId = CrlOcspRef.getInstance(completeCertificateRefs.getObjectAt(i1));
                    for (CrlValidatedID id : otherCertId.getCrlids().getCrls()) {
                        list.add(new CRLRef(id));
                    }
                }
            }
        }

        return list;
    }

    @Override
    public List<OCSPRef> getOCSPRefs() {
        List<OCSPRef> list = new ArrayList<OCSPRef>();

        if (signerInformation.getUnsignedAttributes() != null) {
            Attribute completeRevocationRefsAttr = signerInformation.getUnsignedAttributes().get(
                    PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
            if (completeRevocationRefsAttr != null && completeRevocationRefsAttr.getAttrValues().size() > 0) {
                DERSequence completeRevocationRefs = (DERSequence) completeRevocationRefsAttr.getAttrValues()
                        .getObjectAt(0);
                for (int i1 = 0; i1 < completeRevocationRefs.size(); i1++) {
                    CrlOcspRef otherCertId = CrlOcspRef.getInstance(completeRevocationRefs.getObjectAt(i1));

                    for (OcspResponsesID id : otherCertId.getOcspids().getOcspResponses()) {
                        list.add(new OCSPRef(id, true));
                    }
                }
            }
        }

        return list;
    }

    @Override
    public List<X509CRL> getCRLs() {
        return getCRLSource().getCRLsFromSignature();
    }

    @Override
    public List<BasicOCSPResp> getOCSPs() {
        return getOCSPSource().getOCSPResponsesFromSignature();
    }

    @Override
    public byte[] getSignatureTimestampData() {
        return signerInformation.getSignature();
    }

    @Override
    public byte[] getTimestampX1Data() {
        try {
            ByteArrayOutputStream toTimestamp = new ByteArrayOutputStream();

            toTimestamp.write(signerInformation.getSignature());

            /*
             * We don't include the outer SEQUENCE, only the attrType and attrValues as stated by the TS §6.3.5, NOTE 2
             */
            if (signerInformation.getUnsignedAttributes() != null) {
                toTimestamp.write(signerInformation.getUnsignedAttributes()
                        .get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken).getAttrType().getDEREncoded());
                toTimestamp.write(signerInformation.getUnsignedAttributes()
                        .get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken).getAttrValues().getDEREncoded());
            }

            /* Those are common to Type 1 and Type 2 */
            toTimestamp.write(getTimestampX2Data());

            return toTimestamp.toByteArray();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public byte[] getTimestampX2Data() {
        try {
            ByteArrayOutputStream toTimestamp = new ByteArrayOutputStream();

            /* Those are common to Type 1 and Type 2 */
            if (signerInformation.getUnsignedAttributes() != null) {
                toTimestamp.write(signerInformation.getUnsignedAttributes()
                        .get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs).getAttrType().getDEREncoded());
                toTimestamp.write(signerInformation.getUnsignedAttributes()
                        .get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs).getAttrValues().getDEREncoded());
                toTimestamp.write(signerInformation.getUnsignedAttributes()
                        .get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs).getAttrType().getDEREncoded());
                toTimestamp.write(signerInformation.getUnsignedAttributes()
                        .get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs).getAttrValues().getDEREncoded());
            }

            return toTimestamp.toByteArray();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }

    }

    @Override
    public byte[] getArchiveTimestampData(int index, Document originalDocument) throws IOException {

        ByteArrayOutputStream toTimestamp = new ByteArrayOutputStream();

        ContentInfo contentInfo = cmsSignedData.getContentInfo();
        SignedData signedData = SignedData.getInstance(contentInfo.getContent());

        /* The encapContentInfo should always be present according to the standard, but sometimes it's omitted */
        // 5.4.1
        if (signedData.getEncapContentInfo() == null || signedData.getEncapContentInfo().getContent() == null) {
            /* Detached signatures have either no encapContentInfo in signedData, or it exists but has no eContent */
            if (originalDocument != null) {
                toTimestamp.write(originalDocument.openStream());
            } else {
                throw new RuntimeException("Signature is detached and no original data provided.");
            }
        } else {

            ContentInfo content = signedData.getEncapContentInfo();
            DEROctetString octet = (DEROctetString) content.getContent();

            ContentInfo info2 = new ContentInfo(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1"),
                    new BERConstructedOctetString(octet.getOctets()));
            toTimestamp.write(info2.getEncoded());
        }

        if (signedData.getCertificates() != null) {
            DEROutputStream output = new DEROutputStream(toTimestamp);
            output.writeObject(signedData.getCertificates());
            output.close();
        }

        if (signedData.getCRLs() != null) {
            toTimestamp.write(signedData.getCRLs().getEncoded());
        }

        if (signerInformation.getUnsignedAttributes() != null) {
            ASN1EncodableVector original = signerInformation.getUnsignedAttributes().toASN1EncodableVector();
            List<Attribute> timeStampToRemove = getTimeStampToRemove(index);
            ASN1EncodableVector filtered = new ASN1EncodableVector();
            for (int i = 0; i < original.size(); i++) {
                DEREncodable enc = original.get(i);
                if (!timeStampToRemove.contains(enc)) {
                    filtered.add(original.get(i));
                }
            }
            SignerInformation filteredInfo = SignerInformation.replaceUnsignedAttributes(signerInformation,
                    new AttributeTable(filtered));

            toTimestamp.write(filteredInfo.toASN1Structure().getEncoded());
        }

        return toTimestamp.toByteArray();
    }

    private class AttributeTimeStampComparator implements Comparator<Attribute> {
        @Override
        public int compare(Attribute o1, Attribute o2) {
            try {
                TimeStampToken t1 = new TimeStampToken(new CMSSignedData(o1.getAttrValues().getObjectAt(0)
                        .getDERObject().getDEREncoded()));
                TimeStampToken t2 = new TimeStampToken(new CMSSignedData(o2.getAttrValues().getObjectAt(0)
                        .getDERObject().getDEREncoded()));
                return -t1.getTimeStampInfo().getGenTime().compareTo(t2.getTimeStampInfo().getGenTime());
            } catch (Exception e) {
                throw new RuntimeException("Cannot read original ArchiveTimeStamp", e);
            }
        }
    }

    private List<Attribute> getTimeStampToRemove(int archiveTimeStampToKeep) {
        List<Attribute> ts = new ArrayList<Attribute>();
        /*
         * We need to remove every ArchiveTimeStamp with index < index. Every timestamp is retrieved, then the list is
         * sorted
         */
        if (signerInformation.getUnsignedAttributes() != null) {
            ASN1EncodableVector v = signerInformation.getUnsignedAttributes().getAll(
                    id_aa_ets_archiveTimestampV2);

            for (int i = 0; i < v.size(); i++) {
                DEREncodable enc = v.get(i);
                ts.add((Attribute) enc);
            }

            Collections.sort(ts, new AttributeTimeStampComparator());

            /*
             * TS will contain the list of TimeStamps we must remove the (index) first timestamp. The list is sorted
             * with timestaps descending.
             */
            for (int i = 0; i < archiveTimeStampToKeep; i++) {
                ts.remove(0);
            }

        }
        return ts;
    }
}
