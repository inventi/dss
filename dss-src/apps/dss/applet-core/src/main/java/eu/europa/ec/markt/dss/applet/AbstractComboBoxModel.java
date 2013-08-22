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

import javax.swing.ComboBoxModel;
import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;

/**
 * This abstract class contains the common aspect of ComboBoxModel (listeners).
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public abstract class AbstractComboBoxModel implements ComboBoxModel {

    private List<ListDataListener> listeners = new ArrayList<ListDataListener>();

    protected abstract List<?> getElements();

    private Object selectedElement;

    @Override
    public int getSize() {
        return getElements().size();
    }

    @Override
    public Object getElementAt(int index) {
        return getElements().get(index);
    }

    @Override
    public void addListDataListener(ListDataListener l) {
        listeners.add(l);
    }

    @Override
    public void removeListDataListener(ListDataListener l) {
        listeners.remove(l);
    }

    @Override
    public void setSelectedItem(Object anItem) {
        selectedElement = null;
        for (Object o : getElements()) {
            if (o != null && o.equals(anItem)) {
                selectedElement = anItem;
            }
        }
    }

    @Override
    public Object getSelectedItem() {
        if (selectedElement != null) {
            for (Object o : getElements()) {
                if (selectedElement.equals(o)) {
                    return selectedElement;
                }
            }
        }
        return null;
    }

    /**
     * Send a signal to all listener in order to ask them to refresh the list content
     */
    public void fireUpdateEvent() {
        for (ListDataListener l : listeners) {
            l.contentsChanged(new ListDataEvent(this, 0, 0, 0));
        }
    }

}
