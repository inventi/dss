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

package eu.europa.ec.markt.dss.validation.https;

import eu.europa.ec.markt.dss.CannotFetchDataException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Logger;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.InputStreamRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;

/**
 * 
 * Implementation of HTTPDataLoader using HttpClient. More flexible for HTTPS without having to add the certificate to
 * the JVM TrustStore.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class CommonsHttpDataLoader implements HTTPDataLoader {

    private static final Logger LOG = Logger.getLogger(CommonsHttpDataLoader.class.getName());

    private HttpClient client;

    private ProtocolSocketFactory protocolSocketFactory;

    private String contentType;
    
    private String proxyHost;
    
    private int proxyPort = -1;

    /**
     * 
     * The default constructor for CommonsHttpDataLoader.
     */
    public CommonsHttpDataLoader() {
        this(null);
    }

    /**
     * 
     * The default constructor for CommonsHttpDataLoader.
     * 
     * @param contentType The content type of each request
     */
    public CommonsHttpDataLoader(String contentType) {
        this.contentType = contentType;
    }

    /**
     * @param contentType the contentType to set
     */
    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    /**
     * @param protocolSocketFactory the protocolSocketFactory to set
     */
    public void setProtocolSocketFactory(ProtocolSocketFactory protocolSocketFactory) {
        this.protocolSocketFactory = protocolSocketFactory;
    }

    private HttpClient getClient() throws IOException {
        if (protocolSocketFactory == null) {
            LOG.warning("HTTPS TrustStore undefined, unsing default");
            protocolSocketFactory = new SimpleProtocolSocketFactory();
        }

        if (client == null) {
            client = new HttpClient();
            Protocol myhttps = new Protocol("https", protocolSocketFactory, 443);
            Protocol.registerProtocol("https", myhttps);
        }

        client.getHttpConnectionManager().getParams().setSoTimeout(15000);
        client.getHttpConnectionManager().getParams().setConnectionTimeout(15000);

        if(proxyHost != null && proxyPort != -1) {
            client.getHostConfiguration().setProxy(proxyHost, proxyPort);
        }
        
        return client;
    }

    @Override
    public InputStream get(String URL) throws CannotFetchDataException {
        try {
            LOG.fine("Fetching data from url " + URL);
            GetMethod get = new GetMethod(URL);
            getClient().executeMethod(get);
            if (get.getStatusCode() == 200) {
                return get.getResponseBodyAsStream();
            } else {
                return new ByteArrayInputStream(new byte[0]);
            }
        } catch (IOException ex) {
            throw new CannotFetchDataException(ex, URL);
        }
    }

    @Override
    public InputStream post(String URL, InputStream content) throws CannotFetchDataException {
        try {
            LOG.fine("Post data to url " + URL);
            PostMethod post = new PostMethod(URL);
            RequestEntity requestEntity = new InputStreamRequestEntity(content);
            post.setRequestEntity(requestEntity);
            if (contentType != null) {
                post.setRequestHeader("Content-Type", contentType);
            }
            getClient().executeMethod(post);
            return post.getResponseBodyAsStream();
        } catch (IOException ex) {
            throw new CannotFetchDataException(ex, URL);
        }
    }

    /**
     * @param proxyHost the proxyHost to set
     */
    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }
    
    /**
     * @param proxyPort the proxyPort to set
     */
    public void setProxyPort(int proxyPort) {
        this.proxyPort = proxyPort;
    }

}
