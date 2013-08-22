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
 * Qualification of the certificate according to the QualificationElement of the Trusted List.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class QualificationsVerification {

    private Result QCWithSSCD;
    private Result QCNoSSCD;
    private Result QCSSCDStatusAsInCert;
    private Result QCForLegalPerson;

    /**
     * @return the qCWithSSCD
     */
    public Result getQCWithSSCD() {
        return QCWithSSCD;
    }

    /**
     * @return the qCNoSSCD
     */
    public Result getQCNoSSCD() {
        return QCNoSSCD;
    }

    /**
     * @return the qCSSCDStatusAsInCert
     */
    public Result getQCSSCDStatusAsInCert() {
        return QCSSCDStatusAsInCert;
    }

    /**
     * @return the qCForLegalPerson
     */
    public Result getQCForLegalPerson() {
        return QCForLegalPerson;
    }

    /**
     * The default constructor for QualificationExtensionAnalysis.
     * 
     * @param name
     * @param qCWithSSCD
     * @param qCNoSSCD
     * @param qCSSCDStatusAsInCert
     * @param qCForLegalPerson
     */
    public QualificationsVerification(Result qCWithSSCD, Result qCNoSSCD, Result qCSSCDStatusAsInCert,
            Result qCForLegalPerson) {
        QCWithSSCD = qCWithSSCD;
        QCNoSSCD = qCNoSSCD;
        QCSSCDStatusAsInCert = qCSSCDStatusAsInCert;
        QCForLegalPerson = qCForLegalPerson;
    }

}
