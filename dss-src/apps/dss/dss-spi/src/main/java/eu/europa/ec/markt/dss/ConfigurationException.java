package eu.europa.ec.markt.dss;

import java.util.ResourceBundle;

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


/**
 * Occurs when a configuration is missing/faulty in the DSS server. Because this exception occurs only when the server
 * is not well configured, it's a RuntimeException.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

@SuppressWarnings("serial")
public class ConfigurationException extends RuntimeException {

    private ResourceBundle bundle = ResourceBundle.getBundle("eu/europa/ec/markt/dss/i18n");

    private MSG key;
    /**
     * Supported messages
     */
    public enum MSG {
        CONFIGURE_TSP_SERVER, NOT_PKCS11_LIB
    }

    /**
     * The default constructor for ConfigurationException.
     */
    public ConfigurationException(MSG message) {
        if (message == null) {
            throw new IllegalArgumentException("Cannot build Exception without a message");
        }
        this.key = message;
    }

    @Override
    public String getLocalizedMessage() {
        return bundle.getString(key.toString());
    }

}
