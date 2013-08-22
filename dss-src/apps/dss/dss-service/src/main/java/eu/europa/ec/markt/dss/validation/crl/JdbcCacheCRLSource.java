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

package eu.europa.ec.markt.dss.validation.crl;

import eu.europa.ec.markt.dss.DigestAlgorithm;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Hex;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.JdbcDaoSupport;

/**
 * CRLSource that retrieve information from a JDBC datasource
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class JdbcCacheCRLSource extends JdbcDaoSupport implements CRLSource {

    private static final Logger LOG = Logger.getLogger(JdbcCacheCRLSource.class.getName());

    private OnlineCRLSource cachedSource;

    /**
     * The default constructor for JdbcCRLSource.
     */
    public JdbcCacheCRLSource() {
    }

    /**
     * @param cachedSource the cachedSource to set
     */
    public void setCachedSource(OnlineCRLSource cachedSource) {
        this.cachedSource = cachedSource;
    }

    @Override
    protected void initDao() throws Exception {
        super.initDao();
        /* Create the table ff it doesn't exist. */
        try {
            getJdbcTemplate().queryForInt("SELECT COUNT(*) FROM CACHED_CRL");
        } catch (BadSqlGrammarException ex) {
            getJdbcTemplate().update("CREATE TABLE CACHED_CRL ( ID CHAR(20), DATA LONGVARBINARY)");
            getConnection().commit();
        }
    }

    @Override
    public X509CRL findCrl(X509Certificate certificate, X509Certificate issuerCertificate) throws IOException {

        OnlineCRLSource source = new OnlineCRLSource();
        String crlUrl = source.getCrlUri(certificate);

        if (crlUrl != null) {
            try {
                MessageDigest digest = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName());
                String key = Hex.encodeHexString(digest.digest(crlUrl.getBytes()));

                List<CachedCRL> crls = getJdbcTemplate().query("SELECT * FROM CACHED_CRL WHERE ID = ?",
                        new Object[] { key }, new RowMapper<CachedCRL>() {
                            @Override
                            public CachedCRL mapRow(ResultSet rs, int rowNum) throws SQLException {
                                CachedCRL cached = new CachedCRL();
                                cached.setKey(rs.getString("ID"));
                                cached.setCrl(rs.getBytes("DATA"));
                                return cached;
                            }
                        });

                if (crls.size() == 0) {
                    LOG.info("CRL not in cache");
                    X509CRL originalCRL = cachedSource.findCrl(certificate, issuerCertificate);
                    if (originalCRL != null) {
                        getJdbcTemplate().update("INSERT INTO CACHED_CRL (ID, DATA) VALUES (?,?) ", key,
                                originalCRL.getEncoded());
                        return originalCRL;
                    } else {
                        return null;
                    }
                }

                CachedCRL crl = crls.get(0);

                CertificateFactory factory = CertificateFactory.getInstance("X509");
                X509CRL x509crl = (X509CRL) factory.generateCRL(new ByteArrayInputStream(crl.getCrl()));
                if (x509crl.getNextUpdate().after(new Date())) {
                    LOG.fine("CRL in cache");
                    return x509crl;
                } else {
                    LOG.info("CRL expired");
                    X509CRL originalCRL = cachedSource.findCrl(certificate, issuerCertificate);
                    getJdbcTemplate().update("UPDATE CACHED_CRL SET DATA = ?  WHERE ID = ? ",
                            originalCRL.getEncoded(), key);
                    return originalCRL;
                }

            } catch (NoSuchAlgorithmException e) {
                LOG.info("Cannot instantiate digest for algorithm SHA1 !?");
            } catch (CRLException e) {
                LOG.info("Cannot serialize CRL");
            } catch (CertificateException e) {
                LOG.info("Cannot instanciate X509 Factory");
            }
        }

        return null;
    }

}
