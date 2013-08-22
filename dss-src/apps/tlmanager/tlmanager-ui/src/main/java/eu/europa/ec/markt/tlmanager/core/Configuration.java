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

package eu.europa.ec.markt.tlmanager.core;

import eu.europa.ec.markt.tlmanager.util.Util;

import java.awt.Color;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.TimeZone;
import java.util.logging.Logger;

import javax.swing.JLabel;

/**
 * Main Configuration class for TLManager.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class Configuration {

    private static final Logger LOG = Logger.getLogger(Configuration.class.getName());

    private static final String TL_PROPERTY_FILE = "tlManager.properties";
    private static final String DEFAULT_DELIMITER = "\\|";
    private static final String TUPLE_DELIMITER = ";";
    public static final Color MANDATORY_COLOR = Color.RED;
    public static final Color NORMAL_COLOR = Color.BLACK;
    public static final String SKI_OID = "2.5.29.14";
    
    // Common Settings
    private static final String LOCALE = "tlmanager.common.locale";
//    private static final String TIMEZONE = "tlmanager.common.timezone";
    private static final String MODE = "tlmanager.common.mode"; // expected TL or LOTL
    private static final String MODE_TL = "TL";
    private static final String MODE_LOTL = "LOTL";

    private static final String ADDRESS_TYPE = "tlmanager.common.addresstype";
    private static final String MIME_TYPE = "tlmanager.common.mimetype";
    private static final String TL_TSLTYPE = "tlmanager.tsl.tl.type";
    private static final String LOTL_TSLTYPE = "tlmanager.tsl.lotl.type";

    // Geographic Settings
    private static final String CODE_LANGUAGES = "tlmanager.codes.languages";
    private static final String CODE_COUNTRIES = "tlmanager.codes.countries";

    private static final String QUALIFIER1 = "tlmanager.tsl.tl.qualifier1";
    private static final String QUALIFIER2 = "tlmanager.tsl.tl.qualifier2";
    private static final String ASSERT_ATTRIBUTES = "tlmanager.tsl.tl.assertattribute";

    private static CountryCodes countryCodes;
    private static LanguageCodes languageCodes;
    private static TL tl;
    private static LOTL lotl;

    private static Properties properties;

    private boolean tlMode = true;
    private String[] addressTypes;
    private String[] mimeTypes;
    private String[] qualifier1;
    private String[] qualifier2;
    private String[] assertAttributes;
    private String tlTslType, lotlTslType;
    private Locale locale;
    private TimeZone timeZone;

    private static Configuration instance;

    /**
     * Instantiates a singleton of configuration
     * 
     * @return an instance of configuration
     */
    public static Configuration getInstance() {
        if (instance == null) {
            instance = new Configuration();
        }
        return instance;
    }

    /**
     * Prevent initialisation from the outside
     */
    private Configuration() {
        init();
    }

    private void init() {
        properties = loadProperties();
        initLocale();
        initCommon();
        initCodes();
        initTSL();
    }

    private void initLocale() {
        String localeStr = properties.getProperty(LOCALE);
        locale = null;
        if (localeStr != null && !localeStr.isEmpty()) {
            locale = new Locale(localeStr);
        } else {
            locale = Locale.ENGLISH;
        }
    }
    
//    private void initTimeZone() {
//        String timeZoneStr = properties.getProperty(TIMEZONE);
//        timeZone = null;
//        if (timeZoneStr != null && !timeZoneStr.isEmpty()) {
//            timeZone = TimeZone.getTimeZone(timeZoneStr);
//        } else {
//            timeZone = TimeZone.getDefault();
//        }
//    }

    /**
     * Return the <code>Locale</code>.
     * 
     * @return the locale
     */
    public Locale getLocale() {
        return locale;
    }
    
//    /**
//     * @return the timeZone
//     */
//    public TimeZone getTimeZone() {
//        return timeZone;
//    }

    
    /**
     * @return the name for the timeZone
     */
    public String getTimeZoneName() {
        return TimeZone.getDefault().getDisplayName();
    }
    
    private void initCommon() {
        String mode = properties.getProperty(MODE);
        if (mode != null && mode.equals(MODE_LOTL)) {
            tlMode = false;
        }

        String addType = properties.getProperty(ADDRESS_TYPE);
        if (addType != null) {
            addressTypes = addType.split(DEFAULT_DELIMITER);
        }

        String mimeType = properties.getProperty(MIME_TYPE);
        if (mimeType != null) {
            mimeTypes = mimeType.split(DEFAULT_DELIMITER);
        }

        String qual1 = properties.getProperty(QUALIFIER1);
        if (qual1 != null) {
            qualifier1 = qual1.split(DEFAULT_DELIMITER);
        }

        String qual2 = properties.getProperty(QUALIFIER2);
        if (qual2 != null) {
            qualifier2 = qual2.split(DEFAULT_DELIMITER);
        }

        String assertAtt = properties.getProperty(ASSERT_ATTRIBUTES);
        if (assertAtt != null) {
            assertAttributes = assertAtt.split(DEFAULT_DELIMITER);
        }

        tlTslType = properties.getProperty(TL_TSLTYPE);
        lotlTslType = properties.getProperty(LOTL_TSLTYPE);
    }

    private void initCodes() {
        String countries = properties.getProperty(CODE_COUNTRIES);
        String languages = properties.getProperty(CODE_LANGUAGES);

        countryCodes = new CountryCodes(countries);
        languageCodes = new LanguageCodes(languages);
    }

    private void initTSL() {
        tl = new TL(properties);
        lotl = new LOTL(properties);
    }

    private Properties loadProperties() {
        String resourceName = "/" + TL_PROPERTY_FILE;
        if (MODE_LOTL.equalsIgnoreCase(System.getProperty(MODE))) {
            tlMode = false;
        }
        LOG.info("Loading " + resourceName);
        InputStream fis = null;
        properties = new Properties();
        try {
            fis = this.getClass().getResourceAsStream(resourceName);
            properties.load(fis);
        } catch (IOException ioe) {
            LOG.severe("IO Exception");
            ioe.printStackTrace();
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (Exception e) {
                    LOG.severe(e.toString());
                }
            }
        }
        return properties;
    }

    /**
     * Returns either the lotl, or the tl configuration, depending on the current mode.
     * 
     * @return tl or lotl
     */
    public TSL getTSL() {
        if (tlMode) {
            return tl;
        }
        return lotl;
    }

    /**
     * @return the properties
     */
    public Properties getProperties() {
        return properties;
    }

    /**
     * @return the tlMode
     */
    public Boolean isTlMode() {
        return tlMode;
    }

    /**
     * @return the addressTypes
     */
    public String[] getAddressTypes() {
        return addressTypes;
    }

    /**
     * @return the mimeTypes
     */
    public String[] getMimeTypes() {
        return mimeTypes;
    }

    /**
     * @return the qualifier1
     */
    public String[] getQualifier1() {
        return qualifier1;
    }

    /**
     * @return the qualifier2
     */
    public String[] getQualifier2() {
        return qualifier2;
    }

    /**
     * @return the assertAttributes
     */
    public String[] getAssertAttributes() {
        return assertAttributes;
    }

    /**
     * @return the tlTslType
     */
    public String getTlTslType() {
        return tlTslType;
    }

    /**
     * @return the lotlTslType
     */
    public String getLotlTslType() {
        return lotlTslType;
    }

    /**
     * @return the countryCodes
     */
    public CountryCodes getCountryCodes() {
        return countryCodes;
    }

    /**
     * @return the languageCodes
     */
    public LanguageCodes getLanguageCodes() {
        return languageCodes;
    }

    /**
     * @return the tL
     */
    public TL getTL() {
        return tl;
    }

    /**
     * @return the lOTL
     */
    public LOTL getLOTL() {
        return lotl;
    }

    /**
     * Abstract class for a general TSL.
     *  
     * <p>DISCLAIMER: Project owner DG-MARKT.
     * 
     * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
     * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
     */
    public static abstract class TSL {
        protected String[] parseValueString(String value) {
            if (value != null) {
                return value.split(DEFAULT_DELIMITER);
            }
            return new String[0];
        }

        /**
         * @return the tslTag
         */
        public abstract String getTslTag();

        /**
         * @return the tslVersionIdentifier
         */
        public abstract String getTslVersionIdentifier();

        /**
         * @return the tslType
         */
        public abstract String getTslType();

        /**
         * @return the tsl type inverse
         */
        public abstract String getTslTypeInverse();

        /**
         * @return the tslStatusDeterminationApproach
         */
        public abstract String getTslStatusDeterminationApproach();

        /**
         * @return the tslSchemeTypeCommunityRules
         */
        public abstract String[] getTslSchemeTypeCommunityRules();
    }

    /**
     * 
     * Helper class for maintaining property values for a TL.
     * 
     * <p>
     * DISCLAIMER: Project owner DG-MARKT.
     * 
     * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
     * @author <a href="mailto:dgmarkt.Project-DSS@arhs-consulting.com">ARHS Consulting</a>
     */
    public class TL extends TSL {
        private static final String TSL_TL_TAG = "tlmanager.tsl.tl.tag";
        private static final String TSL_TL_VERSIONIDENTIFIER = "tlmanager.tsl.tl.versionidentifier";
        private static final String TSL_TL_TYPE = "tlmanager.tsl.tl.type";
        private static final String TSL_TL_TYPE_INVERSE = "tlmanager.tsl.lotl.type";
        private static final String TSL_TL_STATUSDETERMINATIONAPPROACH = "tlmanager.tsl.tl.statusdeterminationapproach";
        private static final String TSL_TL_SCHEMETYPECOMMUNITYRULES = "tlmanager.tsl.tl.schemetypecommunityrules";
        // private static final String TSL_TL_ADDRESSTYPE = "tlmanager.tsl.tl.addresstype";
        private static final String TSL_TL_SERVICEIDENTIFIER = "tlmanager.tsl.tl.serviceidentifier";
        private static final String TSL_TL_SERVICESTATUS = "tlmanager.tsl.tl.servicestatus";
        private static final String TSL_TL_QUALIFIER = "tlmanager.tsl.tl.qualifier";
        private static final String TSL_TL_ASSERTATTRIBUTE = "tlmanager.tsl.tl.assertattribute";
        private static final String TSL_TL_KEYUSAGE = "tlmanager.tsl.tl.keyusage";
        private static final String TSL_TL_ADDITIONALSERVICEINFORMATIONURI = "tlmanager.tsl.tl.additionalserviceinformationuri";

        private String tslTag;
        private String tslVersionIdentifier;
        private String tslType;
        private String tslTypeInverse;
        private String tslStatusDeterminationApproach;
        private String[] tslSchemeTypeCommunityRules;
        // private String[] tslAddressType;
        private String[] tslServiceIdentifier;
        private String[] tslServiceStatus;
        private String[] tslQualifier;
        private String[] tslAssertAttribute;
        private String[] tslKeyUsage;
        private String[] tslAdditionalServiceInformationURI;

        /**
         * The default constructor for TL.
         * 
         * @param properties
         */
        public TL(Properties properties) {
            tslTag = properties.getProperty(TSL_TL_TAG);
            tslVersionIdentifier = properties.getProperty(TSL_TL_VERSIONIDENTIFIER);
            tslType = properties.getProperty(TSL_TL_TYPE);
            tslTypeInverse = properties.getProperty(TSL_TL_TYPE_INVERSE);
            tslStatusDeterminationApproach = properties.getProperty(TSL_TL_STATUSDETERMINATIONAPPROACH);
            tslSchemeTypeCommunityRules = parseValueString(properties.getProperty(TSL_TL_SCHEMETYPECOMMUNITYRULES));
            // tslAddressType = parseValueString(properties.getProperty(TSL_TL_ADDRESSTYPE));
            tslServiceIdentifier = parseValueString(properties.getProperty(TSL_TL_SERVICEIDENTIFIER));
            tslServiceStatus = parseValueString(properties.getProperty(TSL_TL_SERVICESTATUS));
            tslQualifier = parseValueString(properties.getProperty(TSL_TL_QUALIFIER));
            tslAssertAttribute = parseValueString(properties.getProperty(TSL_TL_ASSERTATTRIBUTE));
            tslKeyUsage = parseValueString(properties.getProperty(TSL_TL_KEYUSAGE));
            tslAdditionalServiceInformationURI = parseValueString(properties
                    .getProperty(TSL_TL_ADDITIONALSERVICEINFORMATIONURI));
        }

        /** {@inheritDoc} */
        @Override
        public String getTslTag() {
            return tslTag;
        }

        /** {@inheritDoc} */
        @Override
        public String getTslVersionIdentifier() {
            return tslVersionIdentifier;
        }

        /** {@inheritDoc} */
        @Override
        public String getTslType() {
            return tslType;
        }

        /** {@inheritDoc} */
        @Override
        public String getTslTypeInverse() {
            return tslTypeInverse;
        }

        /** {@inheritDoc} */
        @Override
        public String getTslStatusDeterminationApproach() {
            return tslStatusDeterminationApproach;
        }

        /** {@inheritDoc} */
        @Override
        public String[] getTslSchemeTypeCommunityRules() {
            return tslSchemeTypeCommunityRules;
        }

        // /**
        // * @return the tslAddressType
        // */
        // public String[] getTslAddressType() {
        // return tslAddressType;
        // }

        /**
         * @return the tslServiceIdentifier
         */
        public String[] getTslServiceIdentifier() {
            return tslServiceIdentifier;
        }

        /**
         * @return the tslServiceStatus
         */
        public String[] getTslServiceStatus() {
            return tslServiceStatus;
        }

        /**
         * @return the tslQualifier
         */
        public String[] getTslQualifier() {
            return tslQualifier;
        }

        /**
         * @return the tslAssertAttribute
         */
        public String[] getTslAssertAttribute() {
            return tslAssertAttribute;
        }

        /**
         * @return the tslKeyUsage
         */
        public String[] getTslKeyUsage() {
            return tslKeyUsage;
        }

        /**
         * @return the tslAdditionalServiceInformationURI
         */
        public String[] getTslAdditionalServiceInformationURI() {
            return tslAdditionalServiceInformationURI;
        }
    }

    /**
     * 
     * Helper class for maintaining property values for a LOTL.
     * 
     * <p>
     * DISCLAIMER: Project owner DG-MARKT.
     * 
     * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
     * @author <a href="mailto:dgmarkt.Project-DSS@arhs-consulting.com">ARHS Consulting</a>
     */
    public class LOTL extends TSL {
        private static final String TSL_LOTL_TAG = "tlmanager.tsl.lotl.tag";
        private static final String TSL_LOTL_VERSIONIDENTIFIER = "tlmanager.tsl.lotl.versionidentifier";
        private static final String TSL_LOTL_TYPE = "tlmanager.tsl.lotl.type";
        private static final String TSL_LOTL_TYPE_INVERSE = "tlmanager.tsl.tl.type";

        private static final String TSL_LOTL_STATUSDETERMINATIONAPPROACH = "tlmanager.tsl.lotl.statusdeterminationapproach";
        private static final String TSL_LOTL_SCHEMETYPECOMMUNITYRULES = "tlmanager.tsl.lotl.schemetypecommunityrules";

        private String tslTag;
        private String tslVersionIdentifier;
        private String tslType;
        private String tslTypeInverse;
        private String tslStatusDeterminationApproach;
        private String[] tslSchemeTypeCommunityRules;

        /**
         * The default constructor for LOTL.
         * 
         * @param properties
         */
        public LOTL(Properties properties) {
            tslTag = properties.getProperty(TSL_LOTL_TAG);
            tslVersionIdentifier = properties.getProperty(TSL_LOTL_VERSIONIDENTIFIER);
            tslType = properties.getProperty(TSL_LOTL_TYPE);
            tslTypeInverse = properties.getProperty(TSL_LOTL_TYPE_INVERSE);
            tslStatusDeterminationApproach = properties.getProperty(TSL_LOTL_STATUSDETERMINATIONAPPROACH);
            tslSchemeTypeCommunityRules = parseValueString(properties.getProperty(TSL_LOTL_SCHEMETYPECOMMUNITYRULES));
        }

        /** {@inheritDoc} */
        @Override
        public String getTslTag() {
            return tslTag;
        }

        /** {@inheritDoc} */
        @Override
        public String getTslVersionIdentifier() {
            return tslVersionIdentifier;
        }

        /** {@inheritDoc} */
        @Override
        public String getTslType() {
            return tslType;
        }

        /** {@inheritDoc} */
        @Override
        public String getTslTypeInverse() {
            return tslTypeInverse;
        }

        /** {@inheritDoc} */
        @Override
        public String getTslStatusDeterminationApproach() {
            return tslStatusDeterminationApproach;
        }

        /** {@inheritDoc} */
        @Override
        public String[] getTslSchemeTypeCommunityRules() {
            return tslSchemeTypeCommunityRules;
        }
    }

    /**
     * 
     * Helper class for parsing Country Codes from a Property and maintaining them for further access.
     * 
     * <p>
     * DISCLAIMER: Project owner DG-MARKT.
     * 
     * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
     * @author <a href="mailto:dgmarkt.Project-DSS@arhs-consulting.com">ARHS Consulting</a>
     */
    public static class CountryCodes {
        private List<CountryCode> codes = new ArrayList<CountryCode>();

        /**
         * Instantiates a new country codes.
         * 
         * @param property the property
         */
        public CountryCodes(String property) {
            if (property != null && !property.isEmpty()) {
                String[] split = property.split(DEFAULT_DELIMITER);
                for (String str : split) {
                    String[] split2 = str.split(TUPLE_DELIMITER);
                    CountryCode cc = new CountryCode(split2[0], split2[1]);
                    codes.add(cc);
                }
            }
        }

        /**
         * Gets the country codes.
         * 
         * @return the country codes
         */
        public String[] getCodes() {
            if (codes != null) {
                String[] countryCodes = new String[codes.size()];
                int i = 0;
                for (CountryCode code : codes) {
                    countryCodes[i++] = code.getCountryCode();
                }
                return countryCodes;
            }
            return null;
        }

        /**
         * Gets the codes list.
         * 
         * @return the codes list
         */
        public List<String> getCodesList() {
            List<String> list = new ArrayList<String>();
            for (CountryCode code : codes) {
                list.add(code.getCountryCode());
            }
            return list;
        }

        /**
         * Gets the short names.
         * 
         * @return the short names
         */
        public String[] getShortNames() {
            if (codes != null) {
                String[] countryCodes = new String[codes.size()];
                int i = 0;
                for (CountryCode code : codes) {
                    countryCodes[i++] = code.getShortName();
                }
                return countryCodes;
            }
            return null;
        }
    }

    /**
     * Helper class that represents a Country Code
     * 
     * <p>
     * DISCLAIMER: Project owner DG-MARKT.
     * 
     * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
     * @author <a href="mailto:dgmarkt.Project-DSS@arhs-consulting.com">ARHS Consulting</a>
     */
    private static class CountryCode {
        private String shortName;
        private String countryCode;

        /**
         * Instantiates a new country code.
         * 
         * @param shortName the short name
         * @param countryCode the country code
         */
        public CountryCode(String shortName, String countryCode) {
            this.shortName = shortName;
            this.countryCode = countryCode;
        }

        /**
         * @return the shortName
         */
        public String getShortName() {
            return shortName;
        }

        /**
         * @return the countryCode
         */
        public String getCountryCode() {
            return countryCode;
        }
    }

    /**
     * 
     * Helper class for parsing Language Codes from a Property and maintaining them for further access.
     * 
     * <p>
     * DISCLAIMER: Project owner DG-MARKT.
     * 
     * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
     * @author <a href="mailto:dgmarkt.Project-DSS@arhs-consulting.com">ARHS Consulting</a>
     */
    public static class LanguageCodes {
        private List<String> codes = new ArrayList<String>();
        private static final String enCode = "en"; // english language code

        /**
         * Instantiates a new language codes.
         * 
         * @param property the property
         */
        public LanguageCodes(String property) {
            if (property != null && !property.isEmpty()) {
                String[] split = property.split(DEFAULT_DELIMITER);
                for (String str : split) {
                    codes.add(str);
                }
            }
            if (!codes.contains(enCode)) { // at least en
                codes.add(enCode);
            }
        }

        /**
         * @return the first language in the list
         */
        public String getFirstLanguage() {
            return codes.get(0);
        }

        /**
         * @return the english language
         */
        public static String getEnglishLanguage() {
            return enCode;
        }

        /**
         * @return the codes
         */
        public String[] getCodes() {
            Util.sortItems(codes, getEnglishLanguage());
            return codes.toArray(new String[codes.size()]);
        }
    }
}