/**
 * The contents of this file are subject to the OpenMRS Public License
 * Version 1.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://license.openmrs.org
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * Copyright (C) OpenMRS, LLC.  All Rights Reserved.
 */
package org.openmrs.aop;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.LocationAttributeType;
import org.openmrs.User;
import org.openmrs.annotation.AuthorizedAnnotationAttributes;
import org.openmrs.api.APIAuthenticationException;
import org.openmrs.api.LocationService;
import org.openmrs.api.context.Context;
import org.springframework.aop.MethodBeforeAdvice;
import org.xacmlinfo.xacml.pep.agent.PEPAgent;
import org.xacmlinfo.xacml.pep.agent.PEPAgentException;
import org.xacmlinfo.xacml.pep.agent.PEPConfig;
import org.xacmlinfo.xacml.pep.agent.client.PEPClientConfig;

/**
 * This class provides the authorization AOP advice performed before every
 * service layer method call.
 */
public class AuthorizationAdvice implements MethodBeforeAdvice {

	/**
	 * Logger for this class and subclasses
	 */
	protected final Log log = LogFactory.getLog(AuthorizationAdvice.class);

	PEPAgent pepAgent = null;

	public AuthorizationAdvice() {
		try {
			PEPConfig pepConfig = new PEPConfig();
			PEPClientConfig clientConfig = new PEPClientConfig();
			clientConfig.setServerHostName("localhost");
			clientConfig.setServerPort("9443");
			clientConfig.setServerUserName("admin");
			clientConfig.setServerPassword("admin");
			// URI uri = new URI();

			clientConfig.setTrustStoreFile("C:\\utvikling\\wso2is-5.0.0\\repository\\resources\\security\\client-truststore.jks");
			clientConfig.setTrustStorePassword("wso2carbon");
			pepConfig.setPepClientConfig(clientConfig);

			pepAgent = PEPAgent.getInstance(pepConfig);
		} catch (PEPAgentException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Allows us to check whether a user is authorized to access a particular
	 * method.
	 *
	 * @param method
	 * @param args
	 * @param target
	 * @throws Throwable
	 * @should notify listeners about checked privileges
	 */
	@SuppressWarnings({ "unchecked" })
	public void before(Method method, Object[] args, Object target) throws Throwable {
		User user = Context.getAuthenticatedUser();
		String action = null;
		String userName = null;

		if (log.isDebugEnabled()) {
			log.debug("Calling authorization advice before " + method.getName());
		}

		if (log.isDebugEnabled()) {
			log.debug("User " + user);
			if (user != null) {
				log.debug("has roles " + user.getAllRoles());
			}
		}

		AuthorizedAnnotationAttributes attributes = new AuthorizedAnnotationAttributes();
		Collection<String> privileges = attributes.getAttributes(method);
		boolean requireAll = attributes.getRequireAll(method);

		// Only execute if the "secure" method has authorization attributes
		// Iterate through required privileges and return only if the user has
		// one of them
		if (!privileges.isEmpty()) {
			if (pepAgent != null && user != null) {
				String subjecId = user.getUserId().toString();
				String resource = "resource";

				String decision = pepAgent.getDecision(getMultipleXACMLRequest(subjecId, resource, privileges));

				OMElement omElement = AXIOMUtil.stringToOM(decision);
				List<String> results = new ArrayList<String>();

				Iterator iterator = omElement.getChildElements();
				while (iterator.hasNext()) {
					OMElement element = (OMElement) iterator.next();
					if ("Result".equals(element.getLocalName())) {
						String result = element.toString();
						if (result.contains("Permit")) {
							results.add("Permit");
						} else if (result.contains("Deny")) {
							results.add("Deny");
						} else if (result.contains("NotApplicable")) {
							results.add("NotApplicable");
						} else {
							// Indeterminate
							results.add("Indeterminate");
						}
					}

				}
				System.out.println(results.toString());

				if (requireAll && (privileges.size() == 1) && results.contains("Permit")) {
					return;
				}else if (!requireAll && results.contains("Permit")) {
					return;
				} else if (requireAll && !results.contains("Deny") && !results.contains("NotApplicable") && !results.contains("Indeterminate")) {
					return;
				}

				throwUnauthorized(user, method, privileges, results.toString());

			} else {
				throwUnauthorized(user, method);
			}
		} else if (attributes.hasAuthorizedAnnotation(method)) {
			// if there are no privileges defined, just require that
			// the user be authenticated
			if (Context.isAuthenticated() == false) {
				throwUnauthorized(user, method);
			}
		}
	}

	/**
	 * Throws an APIAuthorization exception stating why the user failed
	 *
	 * @param user
	 *            authenticated user
	 * @param method
	 *            acting method
	 * @param attrs
	 *            Collection of String privilege names that the user must have
	 */
	private void throwUnauthorized(User user, Method method, Collection<String> attrs, String XACMLRespons) {
		if (log.isDebugEnabled()) {
			log.debug("User " + user + " is not authorized to access " + method.getName());
		}
		throw new APIAuthenticationException(Context.getMessageSourceService().getMessage("error.privilegesRequired", new Object[] { StringUtils.join(attrs, ",") }, null).toString() + " XACML respons: " + XACMLRespons);
	}

	private void throwUnauthorized(User user, Method method, Collection<String> attrs) {
		if (log.isDebugEnabled()) {
			log.debug("User " + user + " is not authorized to access " + method.getName());
		}
		throw new APIAuthenticationException(Context.getMessageSourceService().getMessage("error.privilegesRequired", new Object[] { StringUtils.join(attrs, ",") }, null).toString());
	}

	/**
	 * Throws an APIAuthorization exception stating why the user failed
	 *
	 * @param user
	 *            authenticated user
	 * @param method
	 *            acting method
	 * @param attrs
	 *            privilege names that the user must have
	 */
	private void throwUnauthorized(User user, Method method, String attr) {
		if (log.isDebugEnabled()) {
			log.debug("User " + user + " is not authorized to access " + method.getName());
		}
		throw new APIAuthenticationException(Context.getMessageSourceService().getMessage("error.privilegesRequired", new Object[] { attr }, null));
	}

	/**
	 * Throws an APIAuthorization exception stating why the user failed
	 *
	 * @param user
	 *            authenticated user
	 * @param method
	 *            acting method
	 */
	private void throwUnauthorized(User user, Method method) {
		if (log.isDebugEnabled()) {
			log.debug("User " + user + " is not authorized to access " + method.getName());
		}
		throw new APIAuthenticationException(Context.getMessageSourceService().getMessage("error.aunthenticationRequired"));
	}

	public static String getMultipleXACMLRequest(String subject, String resource, Collection<String> privileges) {

		String request = "<Request xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" ReturnPolicyIdList=\"false\" CombinedDecision=\"false\">\n" + "<Attributes Category=\"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject\" >\n" + "<Attribute IncludeInResult=\"false\" AttributeId=\"urn:oasis:names:tc:xacml:1.0:subject:subject-id\">\n" + "<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + subject + "</AttributeValue>\n" + "</Attribute>\n" + "</Attributes>\n" + "<Attributes Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:resource\">\n" + "<Attribute AttributeId=\"urn:oasis:names:tc:xacml:1.0:resource:resource-id\" IncludeInResult=\"false\">\n" + "<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + resource + "</AttributeValue>\n" + "</Attribute>\n" + "</Attributes>\n";

		if (privileges != null) {
			for (String action : privileges) {
				request = request + "<Attributes Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:action\">\n" + "<Attribute IncludeInResult=\"true\" AttributeId=\"urn:oasis:names:tc:xacml:1.0:action:action-id\">\n" + "<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + action + "</AttributeValue>\n" + "</Attribute>\n" + "</Attributes>\n";
			}
		}
		request = request + "</Request> ";

		return request;

	}
}
