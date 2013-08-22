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
 * Representation of the Result in the validation report.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class Result {

    /**
     * Supported values
     */
    public enum ResultStatus {
        VALID, // or PASS
        INVALID, // or FAIL
        UNDETERMINED, // or UNKNOWN
        VALID_WITH_WARNINGS, INFORMATION
    }

    private ResultStatus status;
    protected String description;

    /**
     * The default constructor for Result.
     * 
     * @param name
     */
    public Result(ResultStatus status, String description) {
        this.status = status;
        this.description = description;
    }

    /**
     * The default constructor for Result.
     */
    public Result() {
        this(ResultStatus.UNDETERMINED, null);
    }

    /**
     * One-liner to create a Result by asserting something
     * 
     * @param assertion
     * @param statusIfFailed the status to set if the test fails
     */
    private Result(boolean assertion, ResultStatus statusIfFailed) {
        this();
        if (assertion) {
            this.setStatus(ResultStatus.VALID, null);
        } else {
            this.setStatus(statusIfFailed, null);
        }
    }

    /**
     * One-liner to create a Result by asserting something, set to invalid if the assertion fails
     * 
     * @param assertion
     */
    public Result(boolean assertion) {
        this(assertion, ResultStatus.INVALID);
    }

    @Override
    public String toString() {
        return "Result[" + status + "]";
    }

    /**
     * returns whether the check was valid
     * 
     * @return true if valid
     */
    public boolean isValid() {
        return (getStatus() == ResultStatus.VALID);
    }

    /**
     * returns whether the check was invalid
     * 
     * @return true if valid
     */
    public boolean isInvalid() {
        return (getStatus() == ResultStatus.INVALID);
    }

    /**
     * returns whether the check was undetermined
     * 
     * @return true if undetermined
     */
    public boolean isUndetermined() {
        return (getStatus() == ResultStatus.UNDETERMINED);
    }

    /**
     * 
     * @param status
     */
    public void setStatus(ResultStatus status, String description) {
        this.status = status;
        this.description = description;
    }

    /**
     * Set description of the result
     * 
     * @param description
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * @return the result
     */
    public ResultStatus getStatus() {
        return status;
    }

    /**
     * @return the description
     */
    public String getDescription() {
        return description;
    }

}
