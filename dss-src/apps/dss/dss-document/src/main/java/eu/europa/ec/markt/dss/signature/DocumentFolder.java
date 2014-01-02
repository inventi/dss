package eu.europa.ec.markt.dss.signature;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * Immutable
 */
class DocumentFolder implements CompoundDocument {

    private final Document mainDocument;
    private final List<Document> extraDocuments;

    public DocumentFolder(Document mainDoc, Collection<Document> extraDocs) {
        if (mainDoc == null) {
            throw new IllegalArgumentException("Main document cannot be null");
        }
        this.mainDocument = mainDoc;

        if (extraDocs != null && extraDocs.size() > 0) {
            List<Document> extrasList = new ArrayList<Document>(extraDocs.size());
            extrasList.addAll(extraDocs);
            this.extraDocuments = Collections.unmodifiableList(extrasList);
        } else {
            this.extraDocuments = Collections.emptyList();
        }
    }

    public DocumentFolder(Document mainDoc, Document... extraDocs) {
        this(mainDoc, Arrays.asList(extraDocs));
    }

    @Override
    public InputStream openStream() throws IOException {
        return mainDocument.openStream();
    }

    @Override
    public String getName() {
        return mainDocument.getName();
    }

    @Override
    public MimeType getMimeType() {
        return mainDocument.getMimeType();
    }

    @Override
    public List<Document> getExtraDocuments() {
        return extraDocuments;
    }

    @Override
    public Iterator<Document> iterator() {
        return new DocumentIterator();
    }

    private class DocumentIterator implements Iterator<Document> {
        private Iterator<Document> outerIt, innerIt;

        public DocumentIterator() {
        }

        @Override
        public boolean hasNext() {
            return outerIt == null || outerIt.hasNext();
        }

        @Override
        public Document next() {
            if (outerIt == null) { // first
                outerIt = getExtraDocuments().iterator();
                return DocumentFolder.this;
            } else if (innerIt != null) { // has inner
                if (innerIt.hasNext()) {
                    return innerIt.next();
                } else {
                    innerIt = null;
                    return next();
                }
            } else if (outerIt.hasNext()) {
                Document outer = outerIt.next();
                if (outer instanceof CompoundDocument) {
                    innerIt = ((CompoundDocument) outer).iterator();
                    return innerIt.next(); // always have the first one
                } else {
                    return outer;
                }
            } else {
                throw new NoSuchElementException();
            }
        }

        @Override
        public void remove() {
            throw new UnsupportedOperationException("Document iterator is read-only");
        }
    }
}
