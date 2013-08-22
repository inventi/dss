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

import java.util.ArrayList;
import java.util.List;

import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;

/**
 * This abstract class contains common aspects of TreeModel (listeners + abstract getChildren()).
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * @param <R>
 */
public abstract class AbstractTreeModel<R> implements TreeModel {

    private List<TreeModelListener> listeners = new ArrayList<TreeModelListener>();

    private R root;

    /**
     * The default constructor for AbstractTreeModel.
     */
    public AbstractTreeModel(R root) {
        this.root = root;
    }

    @Override
    public R getRoot() {
        return root;
    }

    /**
     * Give the list of children of a parent node
     * 
     * @param parent
     * @return
     */
    public abstract List<?> getChildren(Object parent);

    @SuppressWarnings({ "rawtypes", "unchecked" })
    List<?> getNonNullChildren(Object parent) {
        List list = getChildren(parent);
        List filtered = new ArrayList();
        for (Object o : list) {
            if (!filterThisNode(o)) {
                filtered.add(o);
            }
        }
        return filtered;
    }

    protected boolean filterThisNode(Object child) {
        return child == null;
    }

    @Override
    public Object getChild(Object parent, int index) {
        return getNonNullChildren(parent).get(index);
    }

    @Override
    public int getChildCount(Object parent) {
        return getNonNullChildren(parent).size();
    }

    @Override
    public boolean isLeaf(Object node) {
        return getChildCount(node) == 0;
    }

    @Override
    public void valueForPathChanged(TreePath path, Object newValue) {
    }

    @Override
    public int getIndexOfChild(Object parent, Object child) {
        return getNonNullChildren(parent).indexOf(child);
    }

    @Override
    public void addTreeModelListener(TreeModelListener l) {
        listeners.add(l);
    }

    @Override
    public void removeTreeModelListener(TreeModelListener l) {
        listeners.remove(l);
    }

}
