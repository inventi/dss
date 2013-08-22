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

package eu.europa.ec.markt.dss.applet;

import eu.europa.ec.markt.dss.applet.SignedDocumentTreeModel.TitledNode;
import eu.europa.ec.markt.dss.validation.SignedDocumentValidator;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This CachedTreeModel wrap an TreeModel and delegate all the call to the wrapped tree model. 
 * The values are stored in a cache. 
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class CachedTreeModel extends AbstractTreeModel<SignedDocumentValidator> {

    private AbstractTreeModel<SignedDocumentValidator> wrapped;

    private Map<Object, List<?>> cachedChildren = new HashMap<Object, List<?>>();
    
    /**
     * 
     * The default constructor for CachedTreeModel.
     * @param wrapped
     */
    public CachedTreeModel(AbstractTreeModel<SignedDocumentValidator> wrapped) {
        super(wrapped.getRoot());
        this.wrapped = wrapped;
    }

    @Override
    public List<?> getChildren(Object parent) {
        List<?> cached = cachedChildren.get(parent);
        if(cached == null) {
            cached = wrapped.getChildren(parent);
            cachedChildren.put(parent, cached);
        }
        return cached;
    }

    @Override
    protected boolean filterThisNode(Object child) {
        if (child == null) {
            return true;
        } else if (child instanceof TitledNode) {
            TitledNode titled = (TitledNode) child;
            return titled.getValue() == null;
        }
        return false;
    }

}
