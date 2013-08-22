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

package eu.europa.ec.markt.dss.applet;

import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.validation.CertificateValidity;
import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation.report.CertPathRevocationAnalysis;
import eu.europa.ec.markt.dss.validation.report.CertificateVerification;
import eu.europa.ec.markt.dss.validation.report.QCStatementInformation;
import eu.europa.ec.markt.dss.validation.report.QualificationsVerification;
import eu.europa.ec.markt.dss.validation.report.Result;
import eu.europa.ec.markt.dss.validation.report.RevocationVerificationResult;
import eu.europa.ec.markt.dss.validation.report.SignatureInformation;
import eu.europa.ec.markt.dss.validation.report.SignatureInformation.FinalConclusion;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelA;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelAnalysis;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelBES;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelC;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelEPES;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelLTV;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelT;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelX;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelXL;
import eu.europa.ec.markt.dss.validation.report.SignatureVerification;
import eu.europa.ec.markt.dss.validation.report.TimeInformation;
import eu.europa.ec.markt.dss.validation.report.TimestampVerificationResult;
import eu.europa.ec.markt.dss.validation.report.TrustedListInformation;
import eu.europa.ec.markt.dss.validation.report.ValidationReport;
import eu.europa.ec.markt.dss.validation.tsl.CompositeCriteriaList;
import eu.europa.ec.markt.dss.validation.tsl.KeyUsageCondition;
import eu.europa.ec.markt.dss.validation.tsl.PolicyIdCondition;
import eu.europa.ec.markt.dss.validation.tsl.QualificationElement;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Build the tree model of the validation report.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class SignedDocumentTreeModel extends AbstractTreeModel<SignedDocumentValidator> {

    private static final Logger LOG = Logger.getLogger(SignedDocumentTreeModel.class.getName());

    private ResourceBundle bundle = ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n");

    /**
     * The default constructor for SignedDocumentTreeModel.
     */
    public SignedDocumentTreeModel(File signedFile, FileDocument originalFile, CertificateVerifier verifier)
            throws IOException {
        super(SignedDocumentValidator.fromDocument(new FileDocument(signedFile)));
        if (originalFile != null && originalFile.exists()) {
            getRoot().setExternalContent(originalFile);
        }
        getRoot().setCertificateVerifier(verifier);
    }

    List<?> getChildrenOfRevocationVerificationResult(RevocationVerificationResult result) {
        if (result.getStatus() == CertificateValidity.REVOKED) {
            return Arrays.asList(new TitledNode(bundle.getString("REVOCATION_DATE"), result.getRevocationDate(),
                    true), new TitledNode(bundle.getString("ISSUER"), result.getIssuer(), true), new TitledNode(
                    bundle.getString("ISSUING_TIME"), result.getIssuingTime(), true),
                    new TitledNode(bundle.getString("REVOCATION_DATE"), result.getRevocationDate(), true));
        } else {
            return Collections.emptyList();
        }
    }

    List<?> getChildrenOfTitledNode(TitledNode node) {
        /* Recursive call to directly retrieve the children of the content of the TitledNode */
        if (node.getValue() instanceof Object[] || node.getValue() instanceof List) {
            return getChildren(node.getValue());
        } else if (node.getValue() instanceof Result) {
            Result result = (Result) node.getValue();
            if (result.getDescription() != null && result.getDescription().trim().length() > 0) {
                try {
                    return Arrays.asList(bundle.getString(result.getDescription()));
                } catch (MissingResourceException ex) {
                    LOG.severe("key '" + result.getDescription() + "' not in resource bundle");
                }
            }
            return Collections.emptyList();
        } else if (node.isInline()) {
            return Collections.emptyList();
        } else {
            return Arrays.asList(node.getValue());
        }
    }

    List<?> getChildrenOfTrustedListInformation(TrustedListInformation info) {
        return Arrays.asList(
                new TitledNode(bundle.getString("SERVICE_WAS_FOUND"), info.isServiceWasFound(), true),
                new TitledNode(bundle.getString("TL_WELL_SIGNED"), info.isWellSigned(), true),
                new TitledNode(bundle.getString("TSP_NAME"), info.getTSPName(), true),
                new TitledNode(bundle.getString("TSP_TRADE_NAME"), info.getTSPTradeName(), true),
                new TitledNode(bundle.getString("TSP_POSTAL_ADDRESS"), info.getTSPPostalAddress(), true),
                new TitledNode(bundle.getString("TSP_ELECTRONIC_ADDRESS"), info.getTSPElectronicAddress(), true),
                new TitledNode(bundle.getString("SERVICE_TYPE_IDENTIFIER"), info.getServiceType(), true),
                new TitledNode(bundle.getString("SERVICE_NAME"), info.getServiceName(), true),
                new TitledNode(bundle.getString("CURRENT_STATUS"), info.getCurrentStatus(), true),
                new TitledNode(bundle.getString("CURRENT_STATUS_STARTING_DATE"),
                        info.getCurrentStatusStartingDate(), true),
                new TitledNode(bundle.getString("STATUS_AT_REFERENCE_TIME"), info.getStatusAtReferenceTime(), true),
                new TitledNode(bundle.getString("STATUS_STARTING_DATE_AT_REFERENCE_TIME"), info
                        .getStatusStartingDateAtReferenceTime(), true),
                new TitledNode(bundle.getString("QUALIFICATION_ELEMENT"), info.getQualitificationElements()));
    }

    List<?> getChildrenOfSignatureInformation(SignatureInformation info) {
        return Arrays.asList(
                new TitledNode(bundle.getString("SIGNATURE_STRUCTURE_VERIFICATION"), info
                        .getSignatureLevelAnalysis().getLevelBES().getLevelReached()),
                new TitledNode(bundle.getString("SIGNATURE_VERIFICATION"), info.getSignatureVerification()
                        .getSignatureVerificationResult()),
                bundle.getString("SIGNATURE_ALGORITHM") + info.getSignatureVerification().getSignatureAlgorithm(),
                info.getCertPathRevocationAnalysis(),
                info.getSignatureLevelAnalysis(),
                info.getQualificationsVerification(),
                info.getQcStatementInformation(),
                new TitledNode(bundle.getString("FINAL_CONCLUSION"), info.getFinalConclusion()),
                info.getFinalConclusionComment() == null ? null : new TitledNode(bundle
                        .getString("FINAL_CONCLUSION_COMMENT"), bundle.getString(info.getFinalConclusionComment()),
                        true));
    }

    List<?> getChildrenOfSignatureLevelBES(SignatureLevelBES level) {
        return Arrays.asList(new TitledNode(bundle.getString("CERTIFICATES"), level.getCertificates()),
                new TitledNode(bundle.getString("SIGNING_CERTIFICATE"), level.getSigningCertificate()),
                new TitledNode(bundle.getString("SIGNING_TIME"), level.getSigningTime()),
                new TitledNode(bundle.getString("MIME_TYPE"), level.getContentType()),
                new TitledNode(bundle.getString("LOCATION"), level.getLocation()),
                new TitledNode(bundle.getString("SIGNER_ROLE"), level.getClaimedSignerRoles()), new TitledNode(
                        bundle.getString("COUNTER_SIGNATURE"), level.getCounterSignaturesVerification()),
                new TitledNode(bundle.getString("TIMESTAMP"), level.getTimestampsVerification()));
    }

    List<?> getChildrenOfQualificationElement(QualificationElement element) {
        return Arrays.asList(element.getQualification(), element.getCondition());
    }

    List<?> getChildrenOfQualificationsVerification(QualificationsVerification qual) {
        return Arrays.asList(new TitledNode(bundle.getString("QCWITHSSCD"), qual.getQCWithSSCD()), new TitledNode(
                bundle.getString("QCNOSSCD"), qual.getQCNoSSCD()),
                new TitledNode(bundle.getString("QCSSCDSTATUSASINCERT"), qual.getQCSSCDStatusAsInCert()),
                new TitledNode(bundle.getString("QCFORLEGALPERSON"), qual.getQCForLegalPerson()));
    }

    List<?> getChildrenOfQCStatementInformation(QCStatementInformation info) {
        return Arrays.asList(new TitledNode(bundle.getString("QCP_PRESENCE"), info.getQCPPresent()), new TitledNode(
                bundle.getString("QCPP_PRESENCE"), info.getQCPPlusPresent()),
                new TitledNode(bundle.getString("QCCOMPLIANCE_PRESENCE"), info.getQcCompliancePresent()),
                new TitledNode(bundle.getString("QCSSCD_PRESENCE"), info.getQcSCCDPresent()));
    }

    List<?> getChildrenOfSignatureLevelLTV(SignatureLevelLTV level) {
        return Arrays.asList(
                new TitledNode(bundle.getString("CERTIFICATES_VALUES_VERIFICATION"), level
                        .getCertificateValuesVerification()),
                new TitledNode(bundle.getString("REVOCATION_VALUES_VERIFICATION"), level
                        .getRevocationValuesVerification()));
    }

    List<?> getChildrenOfCertificateVerification(CertificateVerification verif) {
        return Arrays.asList(
                new TitledNode(bundle.getString("ISSUER_NAME"), verif.getCertificate().getIssuerDN(), true),
                new TitledNode(bundle.getString("SERIAL_NUMBER"), verif.getCertificate().getSerialNumber(), true),
                new TitledNode(bundle.getString("VALIDITY_PERIOD_VERIFICATION"), verif
                        .getValidityPeriodVerification()), new TitledNode(bundle.getString("CERTIFICATE_STATUS"),
                        verif.getCertificateStatus()));
    }

    List<?> getChildrenOfCertPathRevocationAnalysis(CertPathRevocationAnalysis path) {
        return Arrays.asList(new TitledNode(bundle.getString("SUMMARY"), path.getSummary()),
                new TitledNode(bundle.getString("CERTIFICATE_VERIFICATION"), path.getCertificatePathVerification()),
                new TitledNode(bundle.getString("TRUSTED_LIST_INFORMATION"), path.getTrustedListInformation()));
    }

    List<?> getChildrenOfSignatureLevelAnalysis(SignatureLevelAnalysis analysis) {
        return Arrays.asList(new TitledNode(bundle.getString("SIGNATURE_FORMAT"), analysis.getSignatureFormat(),
                true), analysis.getLevelBES(), analysis.getLevelEPES(), analysis.getLevelT(), analysis.getLevelC(),
                analysis.getLevelX(), analysis.getLevelXL(), analysis.getLevelA(), analysis.getLevelLTV());
    }

    List<?> getChildrenOfSignedDocumentValidator(SignedDocumentValidator validator) {
        ValidationReport report = validator.validateDocument();
        List<Object> list = new ArrayList<Object>();
        list.add(report.getTimeInformation());
        list.addAll(report.getSignatureInformationList());
        return list;
    }

    List<?> getChildrenOfTimeInformation(TimeInformation time) {
        return Arrays
                .asList(new TitledNode(bundle.getString("VERIFICATION_TIME"), time.getVerificationTime(), true));
    }

    List<?> getChildrenOfSignatureLevelC(SignatureLevelC level) {
        return Arrays.asList(
                new TitledNode(bundle.getString("CERTIFICATE_REFERENCES_VERIFICATION"), level
                        .getCertificateRefsVerification()),
                new TitledNode(bundle.getString("REVOCATION_REFERENCES_VERIFICATION"), level
                        .getRevocationRefsVerification()));
    }

    List<?> getChildrenOfSignatureLevelX(SignatureLevelX level) {
        return Arrays
                .asList(new TitledNode(bundle.getString("SIGNATURE_AND_REFERENCES_TIMESTAMP"), level
                        .getSignatureAndRefsTimestampsVerification()),
                        new TitledNode(bundle.getString("REFERENCES_TIMESTAMP"), level
                                .getReferencesTimestampsVerification()));
    }

    List<?> getChildrenOfSignatureLevelXL(SignatureLevelXL level) {
        return Arrays.asList(
                new TitledNode(bundle.getString("CERTIFICATES_VALUES_VERIFICATION"), level
                        .getCertificateValuesVerification()),
                new TitledNode(bundle.getString("REVOCATION_VALUES_VERIFICATION"), level
                        .getRevocationValuesVerification()));
    }

    List<?> getChildrenOfTimestampVerificationResult(TimestampVerificationResult result) {
        return Arrays.asList(
                new TitledNode(bundle.getString("SERIAL_NUMBER"), result.getSerialNumber(), true),
                new TitledNode(bundle.getString("CREATION_TIME"), result.getCreationTime(), true),
                new TitledNode(bundle.getString("ISSUER_NAME"), result.getIssuerName(), true),
                new TitledNode(bundle.getString("SIGNATURE_VERIFICATION"), result.getSameDigest()),
                new TitledNode(bundle.getString("SIGNATURE_ALGORITHM"), result.getSignatureAlgorithm(), true),
                new TitledNode(bundle.getString("CERTIFICATES_PATH_VERIFICATION"), result
                        .getCertPathUpToTrustedList()));
    }

    List<?> getChildrenOfCompositeCriteriaList(CompositeCriteriaList condition) {
        return Arrays.asList(new TitledNode(bundle.getString("COMPOSITION"), condition.getComposition()),
                new TitledNode(bundle.getString("CRITERIA_LIST"), Arrays.asList(condition.getConditions())));
    }

    List<?> getChildrenOfPolicyIdCondition(PolicyIdCondition condition) {
        return Arrays.asList(condition.getPolicyOid());
    }

    List<?> getChildrenOfKeyUsageCondition(KeyUsageCondition condition) {
        return Arrays.asList(condition.getBit());
    }

    List<?> getChildrenOfSignatureVerification(SignatureVerification verif) {
        return Arrays.asList(verif.getSignatureVerificationResult(), verif.getSignatureAlgorithm());
    }

    @Override
    public List<?> getChildren(Object parent) {

        if (parent instanceof List<?>) {
            return (List<?>) parent;

        } else if (parent instanceof Object[]) {
            return Arrays.asList((Object[]) parent);

        } else if (parent instanceof TitledNode) {
            return getChildrenOfTitledNode((TitledNode) parent);

        } else if (parent instanceof String || parent instanceof CertificateValidity
                || parent instanceof FinalConclusion || parent instanceof X509Certificate
                || parent instanceof Result) {
            return Collections.emptyList();

        } else if (parent instanceof SignatureLevelEPES) {
            return Arrays.asList(new TitledNode(java.util.ResourceBundle.getBundle(
                    "eu/europa/ec/markt/dss/applet/i18n").getString("SIGNATURE_POLICY_IDENTIFIER"),
                    ((SignatureLevelEPES) parent).getPolicyId()));

        } else if (parent instanceof SignatureLevelT) {
            return Arrays.asList(new TitledNode(java.util.ResourceBundle.getBundle(
                    "eu/europa/ec/markt/dss/applet/i18n").getString("SIGNATURE_TIMESTAMP"),
                    ((SignatureLevelT) parent).getSignatureTimestampVerification()));

        } else if (parent instanceof SignatureLevelA) {
            return Arrays.asList(new TitledNode(java.util.ResourceBundle.getBundle(
                    "eu/europa/ec/markt/dss/applet/i18n").getString("ARCHIVE_TIMESTAMP_VERIFICATION"),
                    ((SignatureLevelA) parent).getArchiveTimestampsVerification()));

        } else if (parent instanceof TimestampVerificationResult) {
            return getChildrenOfTimestampVerificationResult((TimestampVerificationResult) parent);

        } else if (parent instanceof SignedDocumentValidator) {
            return getChildrenOfSignedDocumentValidator((SignedDocumentValidator) parent);
        }

        try {
            String simpleName = parent.getClass().getSimpleName();
            String methodName = "getChildrenOf" + simpleName;
            Method method = this.getClass().getDeclaredMethod(methodName, parent.getClass());
            return (List<?>) method.invoke(this, parent);
        } catch (SecurityException e) {
        } catch (NoSuchMethodException e) {
        } catch (IllegalArgumentException e) {
        } catch (IllegalAccessException e) {
        } catch (InvocationTargetException e) {
            LOG.log(Level.SEVERE, "", e);
            throw new RuntimeException(e.getMessage(), e);
        }

        return Collections.emptyList();

    }

    class TitledNode {
        private String title;
        private Object value;
        private boolean inline = false;

        public TitledNode(String title, Object value) {
            this(title, value, false);
        }

        public TitledNode(String title, Object value, boolean inline) {
            this.title = title;
            this.value = value;
            this.inline = inline;
        }

        String getTitle() {
            return title;
        }

        Object getValue() {
            return value;
        }

        public boolean isInline() {
            return inline;
        }

    }
}
