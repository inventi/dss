package eu.europa.ec.markt.dss.signature;

import java.util.List;

public interface CompoundDocument extends Document, Iterable<Document> {
	/**
	 * Extra documents if any. Shall never be null
	 *
	 * @return a list of extra documents or empty list.
	 */
	List<Document> getExtraDocuments();
}
