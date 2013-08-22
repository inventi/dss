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

package eu.europa.ec.markt.dss.signature;

/**
 * Represents an event in the process of creating/validating a e-signature
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class SignatureEvent {

    private Object source;

    private Object data;

    private SignatureEventType type;

    /**
     * 
     * The default constructor for SignatureEvent.
     * 
     * @param source
     * @param type
     * @param data
     */
    public SignatureEvent(Object source, SignatureEventType type, Object data) {
        this.source = source;
        this.type = type;
        this.data = data;
    }

    /**
     * The source of this event
     * 
     * @return
     */
    public Object getSource() {
        return source;
    }

    /**
     * The data associated with this event
     * 
     * @return
     */
    public Object getData() {
        return data;
    }

    /**
     * Type of the event
     * 
     * @return
     */
    public SignatureEventType getType() {
        return type;
    }

}
