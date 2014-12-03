package org.openmrs.xacml;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.xml.stream.XMLStreamException;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.xacmlinfo.xacml.pep.agent.PEPAgent;
import org.xacmlinfo.xacml.pep.agent.PEPAgentException;
import org.xacmlinfo.xacml.pep.agent.PEPConfig;
import org.xacmlinfo.xacml.pep.agent.client.PEPClientConfig;

public class XACMLPEP {

	public static final String INDETERMINATE = "Indeterminate";
	public static final String NOT_APPLICABLE = "NotApplicable";
	public static final String DENY = "Deny";
	public static final String PERMIT = "Permit";
	private PEPAgent pepAgent = null;

	public XACMLPEP(String hostName, String port, String userName, String password, String trustStoreFileURL, String trustStorPassowd) throws PEPAgentException {
		PEPConfig pepConfig = new PEPConfig();
		PEPClientConfig clientConfig = new PEPClientConfig();
		clientConfig.setServerHostName(hostName);
		clientConfig.setServerPort(port);
		clientConfig.setServerUserName(userName);
		clientConfig.setServerPassword(password);
		clientConfig.setTrustStoreFile(trustStoreFileURL);
		clientConfig.setTrustStorePassword(trustStorPassowd);
		pepConfig.setPepClientConfig(clientConfig);
		pepAgent = PEPAgent.getInstance(pepConfig);
	}

	private String getMultipleXACMLRequest(String subject, String resource, Collection<String> privileges) {
		String request = 
				"<Request xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" ReturnPolicyIdList=\"false\" CombinedDecision=\"false\">\n" + 
			    "<Attributes Category=\"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject\" >\n" + 
				    "<Attribute IncludeInResult=\"false\" AttributeId=\"urn:oasis:names:tc:xacml:1.0:subject:subject-id\">\n" + 
				    "<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + subject + "</AttributeValue>\n" + 
				    "</Attribute>\n" + 
			    "</Attributes>\n" + "<Attributes Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:resource\">\n" + 
				    "<Attribute AttributeId=\"urn:oasis:names:tc:xacml:1.0:resource:resource-id\" IncludeInResult=\"false\">\n" + 
				    "<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + resource + "</AttributeValue>\n" + 
				    "</Attribute>\n" + 
			    "</Attributes>\n";

		if (privileges != null) {
			for (String action : privileges) {
				request = request + 
						"<Attributes Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:action\">\n" + 
							"<Attribute IncludeInResult=\"true\" AttributeId=\"urn:oasis:names:tc:xacml:1.0:action:action-id\">\n" + 
							"<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + action + "</AttributeValue>\n" + 
							"</Attribute>\n" + 
						"</Attributes>\n";
			}
		}
		request = request + "</Request> ";

		return request;

	}

	public List<String> getDecisonResults(String subjectId, Collection<String> privileges, String resource) throws PEPAgentException, XMLStreamException, NullPointerException {
		if (pepAgent == null) {
			throw new NullPointerException("PEPAgent not initialized");
		}
		List<String> results = new ArrayList<String>();
			String decision = pepAgent.getDecision(getMultipleXACMLRequest(subjectId, resource, privileges));
			OMElement omElement = AXIOMUtil.stringToOM(decision);

			@SuppressWarnings("rawtypes")
			Iterator iterator = omElement.getChildElements();
			while (iterator.hasNext()) {
				OMElement element = (OMElement) iterator.next();
				if ("Result".equals(element.getLocalName())) {
					String result = element.toString();
					if (result.contains(PERMIT)) {
						results.add(PERMIT);
					} else if (result.contains(DENY)) {
						results.add(DENY);
					} else if (result.contains(NOT_APPLICABLE)) {
						results.add(NOT_APPLICABLE);
					} else {
						// Indeterminate
						results.add(INDETERMINATE);
					}
				}
			}
			return results;
	}
}
