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

/**
 * Information about the QCStatement in the certificate
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class QCStatementInformation {

    private Result QCPPresent;
    private Result QCPPlusPresent;
    private Result QcCompliancePresent;
    private Result QcSCCDPresent;

    /**
     * 
     * @return
     */
    public Result getQCPPresent() {
        return QCPPresent;
    }

    /**
     * 
     * @param qCPPresent
     */
    public void setQCPPresent(Result qCPPresent) {
        QCPPresent = qCPPresent;
    }

    /**
     * 
     * @return
     */
    public Result getQCPPlusPresent() {
        return QCPPlusPresent;
    }

    /**
     * 
     * @param qCPPlusPresent
     */
    public void setQCPPlusPresent(Result qCPPlusPresent) {
        QCPPlusPresent = qCPPlusPresent;
    }

    /**
     * 
     * @return
     */
    public Result getQcCompliancePresent() {
        return QcCompliancePresent;
    }

    /**
     * 
     * @param qcCompliancePresent
     */
    public void setQcCompliancePresent(Result qcCompliancePresent) {
        QcCompliancePresent = qcCompliancePresent;
    }

    /**
     * 
     * @return
     */
    public Result getQcSCCDPresent() {
        return QcSCCDPresent;
    }

    /**
     * 
     * @param qcSCCDPresent
     */
    public void setQcSCCDPresent(Result qcSCCDPresent) {
        QcSCCDPresent = qcSCCDPresent;
    }

    /**
     * The default constructor for QCStatementInformation.
     * 
     * @param name
     * @param qCPPresent
     * @param qCPPlusPresent
     * @param qcCompliancePresent
     * @param qcSCCDPresent
     */
    public QCStatementInformation(Result qCPPresent, Result qCPPlusPresent, Result qcCompliancePresent,
            Result qcSCCDPresent) {
        this.QCPPresent = qCPPresent;
        this.QCPPlusPresent = qCPPlusPresent;
        this.QcCompliancePresent = qcCompliancePresent;
        this.QcSCCDPresent = qcSCCDPresent;
    }

}
