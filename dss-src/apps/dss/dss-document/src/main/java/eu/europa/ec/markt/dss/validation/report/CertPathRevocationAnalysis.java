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

import eu.europa.ec.markt.dss.validation.CertificateValidity;
import eu.europa.ec.markt.dss.validation.ValidationContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.report.Result.ResultStatus;

import java.util.ArrayList;
import java.util.List;

/**
 * Validation information for a Certificate Path (from a end user certificate to the Trusted List)
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class CertPathRevocationAnalysis {

    private Result summary;
    private List<CertificateVerification> certificatePathVerification = new ArrayList<CertificateVerification>();
    private TrustedListInformation trustedListInformation;

    /**
     * 
     * The default constructor for CertPathRevocationAnalysis.
     * 
     * @param ctx
     * @param info
     */
    public CertPathRevocationAnalysis(ValidationContext ctx, TrustedListInformation info) {

        summary = new Result();
        this.trustedListInformation = info;

        if (ctx != null && ctx.getNeededCertificates() != null) {
            for (CertificateAndContext cert : ctx.getNeededCertificates()) {
                CertificateVerification verif = new CertificateVerification(cert, ctx);
                certificatePathVerification.add(verif);
            }
        }

        summary.setStatus(ResultStatus.VALID, null);
        if (certificatePathVerification != null) {
            for (CertificateVerification verif : certificatePathVerification) {
                if (verif.getValidityPeriodVerification().isInvalid()) {
                    summary.setStatus(ResultStatus.INVALID, "certificate.not.valid");
                    break;
                }
                if (verif.getCertificateStatus() != null) {
                    if (verif.getCertificateStatus().getStatus() == CertificateValidity.REVOKED) {
                        summary.setStatus(ResultStatus.INVALID, "certificate.revoked");
                        break;
                    } else if (verif.getCertificateStatus().getStatus() == CertificateValidity.UNKNOWN
                            || verif.getCertificateStatus().getStatus() == null) {
                        summary.setStatus(ResultStatus.UNDETERMINED, "revocation.unknown");
                    }
                } else {
                    summary.setStatus(ResultStatus.UNDETERMINED, "no.revocation.data");
                }
            }
        }

        if (trustedListInformation != null) {
            if (!trustedListInformation.isServiceWasFound()) {
                summary.setStatus(ResultStatus.INVALID, "no.trustedlist.service.was.found");
            }
        } else {
            summary.setStatus(ResultStatus.INVALID, "no.trustedlist.service.was.found");
        }

    }

    /**
     * @return the summary
     */
    public Result getSummary() {
        return summary;
    }

    /**
     * @return the certificatePathVerification
     */
    public List<CertificateVerification> getCertificatePathVerification() {
        return certificatePathVerification;
    }

    /**
     * @return the trustedListInformation
     */
    public TrustedListInformation getTrustedListInformation() {
        return trustedListInformation;
    }

    /**
     * @param summary the summary to set
     */
    public void setSummary(Result summary) {
        this.summary = summary;
    }

    /**
     * @param certificatePathVerification the certificatePathVerification to set
     */
    public void setCertificatePathVerification(List<CertificateVerification> certificatePathVerification) {
        this.certificatePathVerification = certificatePathVerification;
    }

    /**
     * @param trustedListInformation the trustedListInformation to set
     */
    public void setTrustedListInformation(TrustedListInformation trustedListInformation) {
        this.trustedListInformation = trustedListInformation;
    }

}
