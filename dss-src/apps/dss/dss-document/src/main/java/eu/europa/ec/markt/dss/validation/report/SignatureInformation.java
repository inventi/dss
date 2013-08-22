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

package eu.europa.ec.markt.dss.validation.report;

import java.util.logging.Logger;

/**
 * Validation information about a Signature.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class SignatureInformation {

    private static final Logger LOG = Logger.getLogger(SignatureInformation.class.getName());

    /**
     * 
     */
    public enum FinalConclusion {
        QES, AdES_QC, AdES, UNDETERMINED
    }

    private SignatureVerification signatureVerification;
    private CertPathRevocationAnalysis certPathRevocationAnalysis;
    private SignatureLevelAnalysis signatureLevelAnalysis;
    private QualificationsVerification qualificationsVerification;
    private QCStatementInformation qcStatementInformation;
    private FinalConclusion finalConclusion;
    private String finalConclusionComment;

    /**
     * The default constructor for SignatureInformation.
     * 
     * @param name
     * @param signatureStructureVerification
     * @param signatureVerification
     * @param certPathRevocationAnalysis
     * @param signatureLevelAnalysis
     * @param qualificationsVerification
     * @param qcStatementInformation
     * @param finalConclusion
     */
    public SignatureInformation(SignatureVerification signatureVerification,
            CertPathRevocationAnalysis certPathRevocationAnalysis, SignatureLevelAnalysis signatureLevelAnalysis,
            QualificationsVerification qualificationsVerification, QCStatementInformation qcStatementInformation) {

        this.signatureVerification = signatureVerification;
        this.certPathRevocationAnalysis = certPathRevocationAnalysis;
        this.signatureLevelAnalysis = signatureLevelAnalysis;
        this.qualificationsVerification = qualificationsVerification;
        this.qcStatementInformation = qcStatementInformation;

        /* For sake of clarity, we will implement a matrix exactly like the one in FAD */
        int tlContentCase = -1;
        if (certPathRevocationAnalysis.getTrustedListInformation().isServiceWasFound()) {
            tlContentCase = 0;
        }
        if (certPathRevocationAnalysis.getTrustedListInformation().isServiceWasFound()
                && qualificationsVerification != null && qualificationsVerification.getQCWithSSCD().isValid()) {
            tlContentCase = 1;
        }
        if (certPathRevocationAnalysis.getTrustedListInformation().isServiceWasFound()
                && qualificationsVerification != null && qualificationsVerification.getQCNoSSCD().isValid()) {
            tlContentCase = 2;
        }
        if (certPathRevocationAnalysis.getTrustedListInformation().isServiceWasFound()
                && qualificationsVerification != null
                && qualificationsVerification.getQCSSCDStatusAsInCert().isValid()) {
            tlContentCase = 3;
        }
        if (certPathRevocationAnalysis.getTrustedListInformation().isServiceWasFound()
                && qualificationsVerification != null && qualificationsVerification.getQCForLegalPerson().isValid()) {
            tlContentCase = 4;
        }
        if (!certPathRevocationAnalysis.getTrustedListInformation().isServiceWasFound()) {
            // Case 5 and 6 are not discriminable */
            tlContentCase = 5;
            finalConclusionComment = "no.tl.confirmation";
        }
        if (certPathRevocationAnalysis.getTrustedListInformation().isServiceWasFound()
                && !certPathRevocationAnalysis.getTrustedListInformation().isWellSigned()) {
            tlContentCase = 7;
            finalConclusionComment = "unsigned.tl.confirmation";
        }

        int certContentCase = -1;
        if (qcStatementInformation != null && !qcStatementInformation.getQcCompliancePresent().isValid()
                && !qcStatementInformation.getQCPPlusPresent().isValid()
                && qcStatementInformation.getQCPPresent().isValid()
                && !qcStatementInformation.getQcSCCDPresent().isValid()) {
            certContentCase = 0;
        }
        if (qcStatementInformation != null && qcStatementInformation.getQcCompliancePresent().isValid()
                && !qcStatementInformation.getQCPPlusPresent().isValid()
                && qcStatementInformation.getQCPPresent().isValid()
                && !qcStatementInformation.getQcSCCDPresent().isValid()) {
            certContentCase = 1;
        }
        if (qcStatementInformation != null && qcStatementInformation.getQcCompliancePresent().isValid()
                && !qcStatementInformation.getQCPPlusPresent().isValid()
                && qcStatementInformation.getQCPPresent().isValid()
                && qcStatementInformation.getQcSCCDPresent().isValid()) {
            certContentCase = 2;
        }
        if (qcStatementInformation != null && !qcStatementInformation.getQcCompliancePresent().isValid()
                && qcStatementInformation.getQCPPlusPresent().isValid()
                && !qcStatementInformation.getQCPPresent().isValid()
                && !qcStatementInformation.getQcSCCDPresent().isValid()) {
            certContentCase = 3;
        }
        if (qcStatementInformation != null && qcStatementInformation.getQcCompliancePresent().isValid()
                && qcStatementInformation.getQCPPlusPresent().isValid()
                && !qcStatementInformation.getQCPPresent().isValid()
                && !qcStatementInformation.getQcSCCDPresent().isValid()) {
            certContentCase = 4;
        }
        if (qcStatementInformation != null && qcStatementInformation.getQcCompliancePresent().isValid()
                && qcStatementInformation.getQCPPlusPresent().isValid()
                // QCPPlus stronger than QCP. If QCP is present, then it's ok.
                // && !qcStatementInformation.getQCPPresent().isValid()
                && qcStatementInformation.getQcSCCDPresent().isValid()) {
            certContentCase = 5;
        }
        if (qcStatementInformation != null && qcStatementInformation.getQcCompliancePresent().isValid()
                && !qcStatementInformation.getQCPPlusPresent().isValid()
                && !qcStatementInformation.getQCPPresent().isValid()
                && !qcStatementInformation.getQcSCCDPresent().isValid()) {
            certContentCase = 6;
        }
        if (qcStatementInformation != null && !qcStatementInformation.getQcCompliancePresent().isValid()
                && !qcStatementInformation.getQCPPlusPresent().isValid()
                && !qcStatementInformation.getQCPPresent().isValid()
                && qcStatementInformation.getQcSCCDPresent().isValid()) {
            certContentCase = 7;
        }
        if (qcStatementInformation != null && qcStatementInformation.getQcCompliancePresent().isValid()
                && !qcStatementInformation.getQCPPlusPresent().isValid()
                && !qcStatementInformation.getQCPPresent().isValid()
                && qcStatementInformation.getQcSCCDPresent().isValid()) {
            certContentCase = 8;
        }
        if (qcStatementInformation == null
                || (!qcStatementInformation.getQcCompliancePresent().isValid()
                        && !qcStatementInformation.getQCPPlusPresent().isValid()
                        && !qcStatementInformation.getQCPPresent().isValid() && !qcStatementInformation
                        .getQcSCCDPresent().isValid())) {
            certContentCase = 9;
        }

        LOG.info("TLCase : " + (tlContentCase + 1) + " - CertCase : " + (certContentCase + 1));

        try {
            FinalConclusion[][] matrix = {
                    { FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.QES, FinalConclusion.QES,
                            FinalConclusion.QES, FinalConclusion.QES, FinalConclusion.AdES_QC, FinalConclusion.AdES,
                            FinalConclusion.QES, FinalConclusion.AdES },
                    { FinalConclusion.QES, FinalConclusion.QES, FinalConclusion.QES, FinalConclusion.QES,
                            FinalConclusion.QES, FinalConclusion.QES, FinalConclusion.QES, FinalConclusion.AdES,
                            FinalConclusion.QES, FinalConclusion.AdES },
                    { FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.AdES_QC,
                            FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.AdES_QC,
                            FinalConclusion.AdES_QC, FinalConclusion.AdES, FinalConclusion.AdES_QC,
                            FinalConclusion.AdES },
                    { FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.QES, FinalConclusion.QES,
                            FinalConclusion.QES, FinalConclusion.QES, FinalConclusion.AdES_QC, FinalConclusion.AdES,
                            FinalConclusion.QES, FinalConclusion.AdES },
                    { FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.QES, FinalConclusion.QES,
                            FinalConclusion.QES, FinalConclusion.QES, FinalConclusion.AdES_QC, FinalConclusion.AdES,
                            FinalConclusion.QES, FinalConclusion.AdES },
                    { FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.QES, FinalConclusion.QES,
                            FinalConclusion.QES, FinalConclusion.QES, FinalConclusion.AdES_QC, FinalConclusion.AdES,
                            FinalConclusion.QES, FinalConclusion.AdES },
                    { FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.QES, FinalConclusion.QES,
                            FinalConclusion.QES, FinalConclusion.QES, FinalConclusion.AdES_QC, FinalConclusion.AdES,
                            FinalConclusion.QES, FinalConclusion.AdES },
                    { FinalConclusion.AdES_QC, FinalConclusion.AdES_QC, FinalConclusion.QES, FinalConclusion.QES,
                            FinalConclusion.QES, FinalConclusion.QES, FinalConclusion.AdES_QC, FinalConclusion.AdES,
                            FinalConclusion.QES, FinalConclusion.AdES } };
            finalConclusion = matrix[tlContentCase][certContentCase];
        } catch (IndexOutOfBoundsException ex) {
            finalConclusion = FinalConclusion.UNDETERMINED;
        }

    }

    /**
     * @return the signatureVerification
     */
    public SignatureVerification getSignatureVerification() {
        return signatureVerification;
    }

    /**
     * @return the certPathRevocationAnalysis
     */
    public CertPathRevocationAnalysis getCertPathRevocationAnalysis() {
        return certPathRevocationAnalysis;
    }

    /**
     * @return the signatureLevelAnalysis
     */
    public SignatureLevelAnalysis getSignatureLevelAnalysis() {
        return signatureLevelAnalysis;
    }

    /**
     * @return the qualificationsVerification
     */
    public QualificationsVerification getQualificationsVerification() {
        return qualificationsVerification;
    }

    /**
     * @return the qcStatementInformation
     */
    public QCStatementInformation getQcStatementInformation() {
        return qcStatementInformation;
    }

    /**
     * @return the finalConclusion
     */
    public FinalConclusion getFinalConclusion() {
        return finalConclusion;
    }
    
    /**
     * @return the finalConclusionComment
     */
    public String getFinalConclusionComment() {
        return finalConclusionComment;
    }

}
